# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Threat Radar (tr) is a threat assessment and analysis platform for security vulnerability management. It provides Docker container analysis, SBOM generation, and package extraction for security analysis.

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

# Attack path discovery and security analysis
threat-radar graph attack-paths graph.graphml --max-paths 20 -o paths.json
threat-radar graph privilege-escalation graph.graphml -o privesc.json
threat-radar graph lateral-movement graph.graphml -o lateral.json
threat-radar graph attack-surface graph.graphml -o attack-surface.json

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

# Set up environment variables (for AI features)
cp .env.example .env
# Edit .env and add your AI provider API keys
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

The AI integration provides intelligent analysis of vulnerability scan results using Large Language Models (LLMs). It supports both cloud-based models (OpenAI GPT, Anthropic Claude, OpenRouter) and local models (Ollama, LM Studio).

**Key Features:**
- **Vulnerability Analysis**: Assess exploitability, attack vectors, and business impact
- **Prioritization**: Generate ranked lists based on risk and context
- **Remediation**: Create actionable fix recommendations and upgrade paths
- **Flexible Backend**: Support for OpenAI API, Anthropic Claude, OpenRouter unified API, and local models

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
# - OPENROUTER_API_KEY=sk-or-v1-your-key-here (for OpenRouter)
# - AI_PROVIDER=openai  # or 'anthropic', 'openrouter', or 'ollama'
# - AI_MODEL=gpt-4o  # or 'claude-3-5-sonnet-20241022', 'anthropic/claude-3.5-sonnet', 'llama2'
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

#### OpenRouter (Cloud - Unified API)
- **Models**: Access to 100+ models from multiple providers (Anthropic, OpenAI, Google, Meta, etc.)
- **Setup**: Requires API key (`OPENROUTER_API_KEY`)
- **Pros**: Single API for multiple providers, competitive pricing, no rate limits, fallback support
- **Cons**: API costs, data sent to cloud (third-party)
- **Use Cases**: Multi-model testing, cost optimization, high availability with fallbacks

```bash
# Get API key from https://openrouter.ai/keys
export OPENROUTER_API_KEY=sk-or-v1-your-key-here
export AI_PROVIDER=openrouter
export AI_MODEL=anthropic/claude-3.5-sonnet

# Use with any AI command
threat-radar ai analyze scan.json --provider openrouter
threat-radar ai prioritize scan.json --provider openrouter --model openai/gpt-4o
threat-radar ai remediate scan.json --provider openrouter --model google/gemini-pro
```

**Popular OpenRouter Models:**
- `anthropic/claude-3.5-sonnet` (recommended for security analysis)
- `anthropic/claude-3-opus` (highest reasoning capability)
- `openai/gpt-4o` (excellent for structured outputs)
- `openai/gpt-4-turbo` (fast and reliable)
- `google/gemini-pro` (cost-effective alternative)
- `meta-llama/llama-3.1-70b-instruct` (open-source, good performance)
- `google/gemini-flash-1.5` (very fast, low cost)

**Benefits of OpenRouter:**
- **Unified API**: Use multiple AI providers with one integration
- **Cost Optimization**: Switch to cheaper models for less critical analyses
- **High Availability**: Automatic fallbacks if primary model is unavailable
- **No Vendor Lock-in**: Easy to switch between providers
- **Usage Tracking**: Built-in analytics and cost tracking

**Example Multi-Model Workflow:**
```bash
# Use Claude for detailed analysis (best reasoning)
threat-radar ai analyze scan.json \
  --provider openrouter \
  --model anthropic/claude-3.5-sonnet \
  --auto-save

# Use GPT-4o for prioritization (fast structured output)
threat-radar ai prioritize scan.json \
  --provider openrouter \
  --model openai/gpt-4o \
  --auto-save

# Use Gemini for cost-effective remediation
threat-radar ai remediate scan.json \
  --provider openrouter \
  --model google/gemini-pro \
  --auto-save
```

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
- **Executive Dashboard with Key Security Metrics** - Real-time security KPIs, vulnerability trends, and actionable insights
- **Detailed Technical Reports with Attack Paths** - Comprehensive analysis including attack path visualization and exploitation routes
- **Multiple Output Formats** - JSON, Markdown, HTML for different use cases
- **Report Levels** - Executive, Summary, Detailed, Critical-only
- **Customizable Report Templates** - Flexible reporting levels and formats for different audiences
- **Dashboard Data** - Visualization-ready data structures for custom dashboards (Grafana, custom web apps)
- **Trend Analysis** - Compare reports over time to track improvements
- **Automated Report Generation** - Schedule reports via cron, CI/CD pipelines, or custom automation
- **Export Capabilities** - Multiple export formats (JSON, HTML, Markdown) for various use cases

### Report Generation

#### Quick Start: Complete Security Report

```bash
# One-command workflow: Scan, analyze, and report with attack paths
IMAGE="myapp:latest"

# 1. Scan image
threat-radar cve scan-image $IMAGE --auto-save -o scan.json

# 2. Build graph and find attack paths
threat-radar graph build scan.json -o graph.graphml
threat-radar graph attack-paths graph.graphml -o attack-paths.json

# 3. Generate reports in all formats with attack paths
threat-radar report generate scan.json -o report.html --attack-paths attack-paths.json
threat-radar report generate scan.json -o report.pdf --attack-paths attack-paths.json
threat-radar report generate scan.json -o report.md --attack-paths attack-paths.json

# Result: 3 comprehensive reports (HTML, PDF, Markdown) with:
# - Vulnerability analysis
# - Attack path analysis
# - Security recommendations
# - AI-powered insights
```

#### Basic Report Generation

```bash
# Generate comprehensive HTML report with AI executive summary
threat-radar report generate scan-results.json -o report.html -f html

# Executive summary in Markdown (for documentation)
threat-radar report generate scan-results.json -o summary.md -f markdown --level executive

# Executive PDF report (NEW!)
threat-radar report generate scan-results.json -o executive.pdf -f pdf --level executive

# Detailed JSON report with dashboard data
threat-radar report generate scan-results.json -o detailed.json --level detailed

# Critical-only issues (for immediate action)
threat-radar report generate scan-results.json -o critical.json --level critical-only

# Use custom AI model
threat-radar report generate scan-results.json --ai-provider ollama --ai-model llama2

# Without AI executive summary (faster)
threat-radar report generate scan-results.json -o report.json --no-executive
```

#### Reports with Attack Path Analysis (NEW!)

```bash
# Generate attack paths first
threat-radar graph build scan.json -o graph.graphml
threat-radar graph attack-paths graph.graphml -o attack-paths.json

# HTML report with integrated attack paths
threat-radar report generate scan.json \
  -o comprehensive-report.html \
  -f html \
  --attack-paths attack-paths.json

# PDF executive report with attack path analysis
threat-radar report generate scan.json \
  -o executive-with-paths.pdf \
  -f pdf \
  --level executive \
  --attack-paths attack-paths.json \
  --ai-provider openai

# Markdown documentation with attack paths
threat-radar report generate scan.json \
  -o security-analysis.md \
  -f markdown \
  --level detailed \
  --attack-paths attack-paths.json
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

### Attack Path Integration in Reports

**✨ NEW:** Attack paths are now natively integrated into reports! Simply pass the attack paths file when generating reports:

```bash
# Generate report with integrated attack path analysis
threat-radar cve scan-image myapp:production --auto-save -o scan.json
threat-radar graph build scan.json --auto-save -o vuln-graph.graphml
threat-radar graph attack-paths vuln-graph.graphml --max-paths 20 -o attack-paths.json

# Single command to generate comprehensive report with attack paths
threat-radar report generate scan.json \
  -o comprehensive-report.html \
  -f html \
  --attack-paths attack-paths.json

# Or with PDF export
threat-radar report generate scan.json \
  -o executive-report.pdf \
  -f pdf \
  --level executive \
  --attack-paths attack-paths.json \
  --ai-provider openai
```

**Attack path data in reports includes:**
- Attack surface overview (total paths, critical/high counts, risk score)
- Entry points and high-value targets
- Detailed attack path breakdowns with threat levels
- Step-by-step attack sequences
- CVEs exploited in each path
- Privilege escalation and lateral movement opportunities
- Security recommendations based on attack paths

**Attack path reporting workflow:**

1. **Vulnerability Discovery**: Scan images/SBOMs to find CVEs
2. **Graph Building**: Convert scan results to graph database
3. **Attack Path Analysis**: Find exploitation routes from entry points to targets
4. **Report Generation**: Create reports with vulnerability + attack path context
5. **Visualization**: Interactive visualizations of attack routes
6. **Executive Summary**: AI-powered risk assessment considering attack feasibility

**Example: Complete attack-aware report workflow**

```bash
#!/bin/bash
# attack-path-report-workflow.sh

TARGET="production-api:v2.1"

echo "Generating attack path-aware security report for $TARGET..."

# Step 1: Scan for vulnerabilities
echo "1. Scanning for vulnerabilities..."
threat-radar cve scan-image $TARGET --auto-save -o scan.json

# Step 2: Build environment graph with vulnerabilities
echo "2. Building infrastructure graph..."
threat-radar env build-graph production-env.json \
  --merge-scan scan.json \
  --auto-save -o env-graph.graphml

# Step 3: Analyze attack surface
echo "3. Analyzing attack surface..."
threat-radar graph attack-surface env-graph.graphml \
  -o attack-surface.json

# Step 4: Find specific attack paths
echo "4. Discovering attack paths..."
threat-radar graph attack-paths env-graph.graphml \
  --max-paths 50 -o attack-paths.json

# Step 5: Identify privilege escalation opportunities
echo "5. Detecting privilege escalation vectors..."
threat-radar graph privilege-escalation env-graph.graphml \
  -o privesc.json

# Step 6: Generate integrated technical report with attack paths (HTML)
echo "6. Generating technical security report with attack paths..."
threat-radar report generate scan.json \
  -o reports/technical-report.html \
  -f html \
  --level detailed \
  --attack-paths attack-paths.json

# Step 7: Generate executive PDF report with risk context and attack paths
echo "7. Generating executive PDF summary..."
threat-radar report generate scan.json \
  -o reports/executive-summary.pdf \
  -f pdf \
  --level executive \
  --attack-paths attack-paths.json \
  --ai-provider openai

# Step 8: Generate Markdown report for documentation
echo "8. Generating Markdown report..."
threat-radar report generate scan.json \
  -o reports/security-analysis.md \
  -f markdown \
  --level detailed \
  --attack-paths attack-paths.json

# Step 9: Create attack path visualizations
echo "9. Creating visualizations..."
threat-radar visualize attack-paths env-graph.graphml \
  -o reports/attack-paths-viz.html \
  --paths attack-paths.json \
  --max-paths 10

threat-radar visualize topology env-graph.graphml \
  -o reports/topology-security.html \
  --view zones

# Step 10: Export dashboard data
echo "10. Exporting dashboard metrics..."
threat-radar report dashboard-export scan.json \
  -o reports/dashboard-data.json

echo "✅ Complete attack-path-aware report generated!"
echo ""
echo "Reports with integrated attack path analysis:"
echo "   - Technical Report (HTML): reports/technical-report.html"
echo "   - Executive Summary (PDF): reports/executive-summary.pdf"
echo "   - Documentation (Markdown): reports/security-analysis.md"
echo "   - Attack Paths Visualization: reports/attack-paths-viz.html"
echo "   - Topology View: reports/topology-security.html"
echo "   - Dashboard Data: reports/dashboard-data.json"
```

**Benefits of attack path integration:**
- **Contextual Risk Assessment**: Understand which vulnerabilities are actually exploitable
- **Prioritization**: Focus on vulnerabilities in active attack paths
- **Business Impact**: Show executives how attackers could reach critical assets
- **Defense Planning**: Identify where to strengthen security controls
- **Compliance**: Demonstrate security posture for audit requirements

### Customizable Report Templates

Threat Radar provides flexible report customization through report levels and AI-powered insights:

**Report Level Customization:**

```bash
# Executive level - For C-suite and business stakeholders
threat-radar report generate scan.json \
  -o exec-report.md \
  -f markdown \
  --level executive \
  --ai-provider openai

# Summary level - For security team quick reviews
threat-radar report generate scan.json \
  -o summary-report.json \
  --level summary

# Detailed level - For technical analysis and remediation planning
threat-radar report generate scan.json \
  -o detailed-report.html \
  -f html \
  --level detailed

# Critical-only - For incident response and urgent action
threat-radar report generate scan.json \
  -o critical-report.json \
  --level critical-only
```

**AI Model Customization:**

```bash
# Use OpenAI for executive summaries
threat-radar report generate scan.json \
  --ai-provider openai \
  --ai-model gpt-4o

# Use Anthropic Claude for deeper analysis
threat-radar report generate scan.json \
  --ai-provider anthropic \
  --ai-model claude-3-5-sonnet-20241022

# Use local Ollama for privacy
threat-radar report generate scan.json \
  --ai-provider ollama \
  --ai-model llama2

# Disable AI for faster generation
threat-radar report generate scan.json \
  --no-executive
```

**Dashboard Customization:**

```bash
# Include/exclude dashboard data
threat-radar report generate scan.json --dashboard  # Include (default)
threat-radar report generate scan.json --no-dashboard  # Exclude

# Export custom dashboard metrics only
threat-radar report dashboard-export scan.json -o custom-dashboard.json
```

**Format-Specific Customization:**

| Format | Best For | Features | Requirements |
|--------|----------|----------|--------------|
| **JSON** | API integration, automation | Machine-readable, complete data, easy parsing | None |
| **Markdown** | Documentation, GitHub issues | Human-readable, version control friendly, charts | None |
| **HTML** | Presentations, sharing | Beautiful styling, interactive, standalone | None |
| **PDF** | Executive reports, printing | Professional formatting, print-ready, portable | `pip install weasyprint` |

### Automated Report Generation and Scheduling

Automate security reporting with cron jobs, CI/CD pipelines, and custom workflows:

#### Cron-based Scheduled Reports

```bash
# Add to crontab: crontab -e

# Daily vulnerability scan and report (2 AM)
0 2 * * * /usr/local/bin/threat-radar cve scan-image myapp:latest \
  --auto-save && \
  /usr/local/bin/threat-radar report generate \
  storage/cve_storage/myapp_latest_image_*.json \
  -o /var/reports/daily-$(date +\%Y\%m\%d).html \
  -f html --level summary

# Weekly executive report (Monday 9 AM)
0 9 * * 1 /home/user/scripts/weekly-security-report.sh

# Monthly compliance report (1st of month, 8 AM)
0 8 1 * * /home/user/scripts/monthly-compliance.sh

# Hourly critical-only scan for production (business hours)
0 9-17 * * 1-5 /usr/local/bin/threat-radar cve scan-image prod:latest \
  --auto-save && \
  /usr/local/bin/threat-radar report generate \
  storage/cve_storage/prod_latest_*.json \
  --level critical-only \
  -o /var/reports/critical-$(date +\%Y\%m\%d-\%H\%M).json
```

#### GitHub Actions Automated Reporting

```yaml
# .github/workflows/weekly-security-report.yml
name: Weekly Security Report
on:
  schedule:
    - cron: '0 9 * * 1'  # Every Monday at 9 AM
  workflow_dispatch:  # Allow manual trigger

jobs:
  generate-report:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Install Threat Radar
        run: pip install threat-radar

      - name: Scan all production images
        run: |
          for image in frontend:prod backend:prod api:prod; do
            threat-radar cve scan-image $image \
              --auto-save -o scan-${image/:/-}.json
          done

      - name: Generate comprehensive report
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          threat-radar report generate scan-*.json \
            -o weekly-report.html \
            -f html \
            --level detailed \
            --ai-provider openai

      - name: Generate executive summary
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          threat-radar report generate scan-*.json \
            -o executive-summary.md \
            -f markdown \
            --level executive \
            --ai-provider openai

      - name: Export dashboard data
        run: |
          threat-radar report dashboard-export scan-*.json \
            -o dashboard-metrics.json

      - name: Upload reports to S3
        run: |
          aws s3 cp weekly-report.html s3://security-reports/$(date +%Y-%m-%d)/
          aws s3 cp executive-summary.md s3://security-reports/$(date +%Y-%m-%d)/
          aws s3 cp dashboard-metrics.json s3://security-reports/$(date +%Y-%m-%d)/

      - name: Send Slack notification
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "Weekly security report generated",
              "attachments": [{
                "color": "good",
                "fields": [
                  {"title": "Report Date", "value": "${{ github.event.repository.updated_at }}", "short": true},
                  {"title": "View Report", "value": "<https://security-reports.s3.amazonaws.com/${{ github.run_id }}/weekly-report.html|Click Here>", "short": true}
                ]
              }]
            }
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK }}

      - name: Create GitHub Issue for critical findings
        run: |
          CRITICAL=$(jq '.summary.critical' scan-*.json | jq -s 'add')
          if [ $CRITICAL -gt 0 ]; then
            gh issue create \
              --title "⚠️  $CRITICAL Critical Vulnerabilities Found - $(date +%Y-%m-%d)" \
              --body-file executive-summary.md \
              --label security,critical
          fi
```

#### Jenkins Pipeline for Continuous Reporting

```groovy
// Jenkinsfile
pipeline {
    agent any

    triggers {
        cron('H 2 * * *')  // Daily at 2 AM
    }

    environment {
        OPENAI_API_KEY = credentials('openai-api-key')
    }

    stages {
        stage('Scan Images') {
            steps {
                script {
                    def images = ['frontend:latest', 'backend:latest', 'api:latest']

                    images.each { image ->
                        sh """
                            threat-radar cve scan-image ${image} \
                                --auto-save \
                                -o scan-${image.replaceAll(':', '-')}.json
                        """
                    }
                }
            }
        }

        stage('Generate Reports') {
            parallel {
                stage('Technical Report') {
                    steps {
                        sh '''
                            threat-radar report generate scan-*.json \
                                -o technical-report.html \
                                -f html \
                                --level detailed
                        '''
                    }
                }

                stage('Executive Report') {
                    steps {
                        sh '''
                            threat-radar report generate scan-*.json \
                                -o executive-report.md \
                                -f markdown \
                                --level executive \
                                --ai-provider openai
                        '''
                    }
                }

                stage('Dashboard Export') {
                    steps {
                        sh '''
                            threat-radar report dashboard-export scan-*.json \
                                -o dashboard-data.json
                        '''
                    }
                }
            }
        }

        stage('Publish Reports') {
            steps {
                publishHTML([
                    reportDir: '.',
                    reportFiles: 'technical-report.html',
                    reportName: 'Security Report'
                ])

                archiveArtifacts artifacts: '*.html,*.md,*.json'

                // Email reports
                emailext(
                    subject: "Daily Security Report - ${new Date().format('yyyy-MM-dd')}",
                    body: readFile('executive-report.md'),
                    to: 'security-team@company.com',
                    attachmentsPattern: 'technical-report.html'
                )
            }
        }

        stage('Alert on Critical Issues') {
            steps {
                script {
                    def criticalCount = sh(
                        script: "jq '.summary.critical' scan-*.json | jq -s 'add'",
                        returnStdout: true
                    ).trim().toInteger()

                    if (criticalCount > 0) {
                        slackSend(
                            color: 'danger',
                            message: "⚠️  ${criticalCount} critical vulnerabilities found! View report: ${env.BUILD_URL}"
                        )
                    }
                }
            }
        }
    }
}
```

#### Custom Python Automation Script

```python
#!/usr/bin/env python3
"""
Automated security reporting script.
Run via cron: 0 2 * * * /usr/bin/python3 /opt/scripts/auto-report.py
"""

import subprocess
import json
from datetime import datetime
from pathlib import Path
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

def run_scan(image):
    """Scan Docker image for vulnerabilities."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"scan_{image.replace(':', '_')}_{timestamp}.json"

    cmd = [
        "threat-radar", "cve", "scan-image", image,
        "--auto-save", "-o", output_file
    ]

    subprocess.run(cmd, check=True)
    return output_file

def generate_report(scan_files, report_type="detailed"):
    """Generate vulnerability report."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if report_type == "executive":
        output_file = f"executive_report_{timestamp}.md"
        format_type = "markdown"
    else:
        output_file = f"detailed_report_{timestamp}.html"
        format_type = "html"

    cmd = [
        "threat-radar", "report", "generate",
        *scan_files,
        "-o", output_file,
        "-f", format_type,
        "--level", report_type,
        "--ai-provider", "openai"
    ]

    subprocess.run(cmd, check=True)
    return output_file

def send_email_report(report_file, recipients):
    """Send report via email."""
    sender = "security-automation@company.com"

    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = ", ".join(recipients)
    msg['Subject'] = f"Security Report - {datetime.now().strftime('%Y-%m-%d')}"

    body = "Please find attached the latest security vulnerability report."
    msg.attach(MIMEText(body, 'plain'))

    with open(report_file, "rb") as f:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(f.read())

    encoders.encode_base64(part)
    part.add_header('Content-Disposition', f"attachment; filename= {report_file}")
    msg.attach(part)

    server = smtplib.SMTP('smtp.company.com', 587)
    server.starttls()
    server.login("automation@company.com", "password")
    server.send_message(msg)
    server.quit()

def check_critical_threshold(scan_files):
    """Check if critical vulnerabilities exceed threshold."""
    total_critical = 0

    for scan_file in scan_files:
        with open(scan_file) as f:
            data = json.load(f)
            total_critical += data.get('severity_counts', {}).get('critical', 0)

    return total_critical

def main():
    # Configuration
    images_to_scan = [
        "frontend:production",
        "backend:production",
        "api:production",
        "worker:production"
    ]

    executive_recipients = ["cto@company.com", "ciso@company.com"]
    team_recipients = ["security-team@company.com"]

    # Scan all images
    print("Starting automated security scan...")
    scan_files = []

    for image in images_to_scan:
        print(f"Scanning {image}...")
        scan_file = run_scan(image)
        scan_files.append(scan_file)

    # Generate reports
    print("Generating reports...")
    exec_report = generate_report(scan_files, "executive")
    tech_report = generate_report(scan_files, "detailed")

    # Check for critical issues
    critical_count = check_critical_threshold(scan_files)

    if critical_count > 0:
        print(f"⚠️  WARNING: {critical_count} critical vulnerabilities found!")
        # Send urgent notification
        send_email_report(tech_report, team_recipients + executive_recipients)
    else:
        # Send routine reports
        send_email_report(exec_report, executive_recipients)
        send_email_report(tech_report, team_recipients)

    print("✅ Automated reporting complete!")

if __name__ == "__main__":
    main()
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

# 2. Build vulnerability graph
threat-radar graph build scan-${WEEK}.json --auto-save -o graph-${WEEK}.graphml

# 3. Discover attack paths
threat-radar graph attack-paths graph-${WEEK}.graphml \
  --max-paths 30 -o attack-paths-${WEEK}.json

# 4. Generate comprehensive HTML report for security team with attack paths
threat-radar report generate scan-${WEEK}.json \
  -o reports/detailed-${WEEK}.html \
  -f html \
  --level detailed \
  --attack-paths attack-paths-${WEEK}.json \
  --ai-provider openai

# 5. Generate executive PDF summary for leadership meeting
threat-radar report generate scan-${WEEK}.json \
  -o reports/exec-${WEEK}.pdf \
  -f pdf \
  --level executive \
  --attack-paths attack-paths-${WEEK}.json \
  --ai-provider openai

# 6. Export dashboard data for Grafana monitoring
threat-radar report dashboard-export scan-${WEEK}.json \
  -o dashboards/metrics-${WEEK}.json

# 7. Compare with last week's scan
if [ -f "scan-${LAST_WEEK}.json" ]; then
  threat-radar report compare \
    scan-${LAST_WEEK}.json \
    scan-${WEEK}.json \
    -o reports/trend-${WEEK}.json

  # Alert if situation is worsening
  TREND=$(jq -r '.trend' reports/trend-${WEEK}.json)
  if [ "$TREND" = "worsening" ]; then
    send_slack_alert "⚠️  Security posture worsening! Check reports/exec-${WEEK}.pdf"
  fi
fi

# 8. Send reports via email/Slack
send_report_email reports/exec-${WEEK}.pdf "leadership@company.com"
send_slack_report reports/detailed-${WEEK}.html "#security-team"

echo "✅ Weekly security report complete!"
echo "   - Technical Report: reports/detailed-${WEEK}.html"
echo "   - Executive Summary: reports/exec-${WEEK}.pdf"
echo "   - Dashboard Data: dashboards/metrics-${WEEK}.json"
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

      - name: Build vulnerability graph
        run: |
          threat-radar graph build scan-results.json \
            --auto-save -o vuln-graph.graphml

      - name: Discover attack paths
        run: |
          threat-radar graph attack-paths vuln-graph.graphml \
            --max-paths 20 -o attack-paths.json

      - name: Generate PR comment report with attack paths
        if: github.event_name == 'pull_request'
        run: |
          threat-radar report generate scan-results.json \
            -o pr-report.md \
            -f markdown \
            --level summary \
            --attack-paths attack-paths.json

          gh pr comment ${{ github.event.pull_request.number }} \
            --body-file pr-report.md

      - name: Generate executive PDF report
        if: github.ref == 'refs/heads/main'
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        run: |
          threat-radar report generate scan-results.json \
            -o executive-report.pdf \
            -f pdf \
            --level executive \
            --attack-paths attack-paths.json \
            --ai-provider openai

      - name: Upload reports as artifacts
        uses: actions/upload-artifact@v3
        if: always()
        with:
          name: security-reports
          path: |
            scan-results.json
            critical-report.json
            pr-report.md
            executive-report.pdf
            attack-paths.json
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

# Scan all production images and generate reports
for IMAGE in "${IMAGES[@]}"; do
  echo "Scanning $IMAGE..."
  SAFE_NAME="${IMAGE//:/─}"

  # Scan for vulnerabilities
  threat-radar cve scan-image $IMAGE \
    -o "compliance/${SAFE_NAME}-${QUARTER}.json" \
    --auto-save

  # Build graph and find attack paths
  threat-radar graph build "compliance/${SAFE_NAME}-${QUARTER}.json" \
    -o "compliance/${SAFE_NAME}-graph.graphml"

  threat-radar graph attack-paths "compliance/${SAFE_NAME}-graph.graphml" \
    --max-paths 30 -o "compliance/${SAFE_NAME}-paths.json"

  # Generate detailed HTML report with attack paths
  threat-radar report generate \
    "compliance/${SAFE_NAME}-${QUARTER}.json" \
    -o "compliance/${SAFE_NAME}-${QUARTER}.html" \
    -f html \
    --level detailed \
    --attack-paths "compliance/${SAFE_NAME}-paths.json" \
    --ai-provider openai

  # Generate executive PDF for auditors
  threat-radar report generate \
    "compliance/${SAFE_NAME}-${QUARTER}.json" \
    -o "compliance/${SAFE_NAME}-${QUARTER}.pdf" \
    -f pdf \
    --level executive \
    --attack-paths "compliance/${SAFE_NAME}-paths.json" \
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

### Export Capabilities

Threat Radar supports multiple export formats for reports and visualizations:

#### Supported Report Export Formats

| Format | File Extension | Use Case | Features | Requirements |
|--------|---------------|----------|----------|--------------|
| **JSON** | `.json` | API integration, automation, archival | Machine-readable, complete structured data, easy parsing | None |
| **Markdown** | `.md`, `.markdown` | Documentation, GitHub/GitLab, wikis | Human-readable, version control friendly, supports tables and charts | None |
| **HTML** | `.html` | Web viewing, presentations, sharing | Beautiful styling, interactive, standalone, no dependencies | None |
| **PDF** | `.pdf` | Print-ready reports, executive summaries | Professional formatting, print-ready, email-friendly | `pip install weasyprint` |

**Export Format Examples:**

```bash
# Export as JSON (default) - Best for automation
threat-radar report generate scan.json -o report.json -f json

# Export as Markdown - Best for documentation
threat-radar report generate scan.json -o report.md -f markdown

# Export as HTML - Best for presentations
threat-radar report generate scan.json -o report.html -f html

# Export as PDF - Best for executives and printing
threat-radar report generate scan.json -o report.pdf -f pdf

# Auto-detect format from file extension
threat-radar report generate scan.json -o report.html  # Automatically uses HTML
threat-radar report generate scan.json -o report.md    # Automatically uses Markdown
threat-radar report generate scan.json -o report.pdf   # Automatically uses PDF
```

**Note:** PDF export requires weasyprint:
```bash
# Install weasyprint for PDF export
pip install weasyprint

# Or install threat-radar with PDF support
pip install threat-radar[pdf]
```

#### Dashboard Export Formats

Dashboard data is exported in JSON format optimized for visualization tools:

```bash
# Export dashboard data for Grafana
threat-radar report dashboard-export scan.json -o dashboard.json

# Dashboard data structure includes:
# - Summary cards (total vulnerabilities, critical count, CVSS scores)
# - Severity distribution chart data
# - Top vulnerable packages chart data
# - CVSS score histogram
# - Package type breakdown
# - Critical items list
```

**Integration examples:**

```bash
# Export for Grafana dashboard
threat-radar report dashboard-export scan.json -o /var/grafana/data/security-metrics.json

# Export for custom web dashboard
threat-radar report dashboard-export scan.json | \
  curl -X POST https://dashboard.company.com/api/metrics -d @-

# Export for Splunk/ELK
threat-radar report generate scan.json -f json | \
  curl -X POST https://splunk.company.com:8088/services/collector -d @-
```

#### Visualization Export Formats

Graph visualizations support multiple export formats via the `visualize export` command:

| Format | Extension | Use Case | Requirements |
|--------|-----------|----------|--------------|
| **HTML** | `.html` | Interactive web visualization | None |
| **PNG** | `.png` | Static images for reports | Requires `kaleido` |
| **SVG** | `.svg` | Scalable vector graphics | Requires `kaleido` |
| **PDF** | `.pdf` | Print-ready documents | Requires `kaleido` |
| **JSON** | `.json` | Custom web applications | None |
| **DOT** | `.dot` | Graphviz processing | Requires `pydot` |
| **GEXF** | `.gexf` | Gephi import | None |
| **Cytoscape** | `.json` | Cytoscape.js | None |

```bash
# Export graph visualization as HTML
threat-radar visualize export graph.graphml -o viz.html --format html

# Export as high-resolution PNG
threat-radar visualize export graph.graphml -o viz.png --format png

# Export as PDF for reports
threat-radar visualize export graph.graphml -o viz.pdf --format pdf

# Export multiple formats at once
threat-radar visualize export graph.graphml -o viz \
  --format html --format png --format pdf
```

#### Complete Export Workflow Example

```bash
#!/bin/bash
# complete-export-workflow.sh - Generate all report formats

TARGET="myapp:production"
DATE=$(date +%Y-%m-%d)
REPORT_DIR="reports/${DATE}"

mkdir -p $REPORT_DIR

echo "Generating complete security report suite for $TARGET..."

# 1. Scan for vulnerabilities
echo "Step 1: Scanning for vulnerabilities..."
threat-radar cve scan-image $TARGET --auto-save -o scan.json

# 2. Build graph and analyze attack paths
echo "Step 2: Building vulnerability graph..."
threat-radar graph build scan.json --auto-save -o graph.graphml

echo "Step 3: Discovering attack paths..."
threat-radar graph attack-paths graph.graphml \
  --max-paths 30 -o attack-paths.json

# 3. Export reports in all formats with attack paths
echo "Step 4: Generating reports in all formats..."

# JSON - For automation
threat-radar report generate scan.json \
  -o $REPORT_DIR/detailed-report.json \
  -f json \
  --level detailed \
  --attack-paths attack-paths.json

# Markdown - For documentation
threat-radar report generate scan.json \
  -o $REPORT_DIR/executive-summary.md \
  -f markdown \
  --level executive \
  --attack-paths attack-paths.json \
  --ai-provider openai

# HTML - For presentations
threat-radar report generate scan.json \
  -o $REPORT_DIR/technical-report.html \
  -f html \
  --level detailed \
  --attack-paths attack-paths.json

# PDF - For executives and printing
threat-radar report generate scan.json \
  -o $REPORT_DIR/executive-report.pdf \
  -f pdf \
  --level executive \
  --attack-paths attack-paths.json \
  --ai-provider openai

# 4. Export dashboard data
echo "Step 5: Exporting dashboard data..."
threat-radar report dashboard-export scan.json \
  -o $REPORT_DIR/dashboard-data.json

# 5. Export visualizations
echo "Step 6: Creating visualizations..."
threat-radar visualize export graph.graphml \
  -o $REPORT_DIR/graph-viz \
  --format html --format png --format pdf

threat-radar visualize attack-paths graph.graphml \
  -o $REPORT_DIR/attack-paths-viz.html \
  --paths attack-paths.json

# 6. Create archive
echo "Step 7: Creating archive..."
tar -czf security-report-${DATE}.tar.gz $REPORT_DIR/

echo ""
echo "✅ Complete export ready!"
echo ""
echo "Generated reports with attack path analysis:"
echo "   - JSON (automation): $REPORT_DIR/detailed-report.json"
echo "   - Markdown (docs): $REPORT_DIR/executive-summary.md"
echo "   - HTML (web): $REPORT_DIR/technical-report.html"
echo "   - PDF (print): $REPORT_DIR/executive-report.pdf"
echo "   - Dashboard data: $REPORT_DIR/dashboard-data.json"
echo "   - Graph visualization: $REPORT_DIR/graph-viz.html"
echo "   - Attack paths viz: $REPORT_DIR/attack-paths-viz.html"
echo ""
echo "Archive: security-report-${DATE}.tar.gz"
```

#### Export to Cloud Storage

```bash
# Upload to AWS S3
threat-radar report generate scan.json -o report.html -f html
aws s3 cp report.html s3://security-reports/$(date +%Y/%m/%d)/

# Upload to Google Cloud Storage
threat-radar report generate scan.json -o report.json -f json
gsutil cp report.json gs://security-reports/$(date +%Y/%m/%d)/

# Upload to Azure Blob Storage
threat-radar report generate scan.json -o report.md -f markdown
az storage blob upload \
  --container-name security-reports \
  --name $(date +%Y/%m/%d)/report.md \
  --file report.md
```

#### Export API Integration

```python
#!/usr/bin/env python3
"""Export reports to various systems via API."""

import subprocess
import json
import requests
from pathlib import Path

def export_to_jira(report_file):
    """Create Jira ticket with security findings."""
    with open(report_file) as f:
        report = json.load(f)

    summary = report['summary']
    critical_count = summary['critical']
    high_count = summary['high']

    issue_data = {
        "fields": {
            "project": {"key": "SEC"},
            "summary": f"Security Scan: {critical_count} Critical, {high_count} High",
            "description": f"Vulnerability scan results attached. Total: {summary['total_vulnerabilities']}",
            "issuetype": {"name": "Bug"},
            "priority": {"name": "Critical" if critical_count > 0 else "High"},
            "labels": ["security", "vulnerability-scan"]
        }
    }

    response = requests.post(
        "https://jira.company.com/rest/api/2/issue",
        json=issue_data,
        auth=("user", "api-token")
    )

    return response.json()

def export_to_servicenow(report_file):
    """Create ServiceNow incident."""
    with open(report_file) as f:
        report = json.load(f)

    incident_data = {
        "short_description": f"Security Vulnerabilities Detected",
        "description": json.dumps(report['summary'], indent=2),
        "urgency": "1" if report['summary']['critical'] > 0 else "2",
        "impact": "1",
        "assignment_group": "Security Operations"
    }

    response = requests.post(
        "https://servicenow.company.com/api/now/table/incident",
        json=incident_data,
        auth=("user", "password")
    )

    return response.json()

def export_to_slack(report_file):
    """Send report summary to Slack."""
    with open(report_file) as f:
        report = json.load(f)

    summary = report['summary']

    message = {
        "text": "Security Scan Complete",
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Security Scan Results*\n\nTotal Vulnerabilities: {summary['total_vulnerabilities']}\nCritical: {summary['critical']}\nHigh: {summary['high']}\nMedium: {summary['medium']}"
                }
            }
        ]
    }

    requests.post(
        "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
        json=message
    )

# Example usage
if __name__ == "__main__":
    # Generate report
    subprocess.run([
        "threat-radar", "report", "generate",
        "scan.json", "-o", "report.json", "-f", "json"
    ])

    # Export to various systems
    export_to_jira("report.json")
    export_to_servicenow("report.json")
    export_to_slack("report.json")
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

### Attack Path Discovery Commands

Threat Radar includes advanced attack path discovery capabilities for identifying potential security attack vectors through your infrastructure.

#### Find Attack Paths

Discover shortest attack paths from entry points to high-value targets:

```bash
# Find attack paths in a graph
threat-radar graph attack-paths graph.graphml

# Limit number of paths and save to JSON
threat-radar graph attack-paths graph.graphml \
  --max-paths 20 \
  --max-length 10 \
  -o attack-paths.json

# Example output shows:
# - Threat level (CRITICAL/HIGH/MEDIUM/LOW)
# - Attack path steps with descriptions
# - CVEs exploited at each step
# - Total CVSS score and exploitability rating
```

**What it analyzes:**
- Automatically identifies potential entry points (internet-facing assets, DMZ zones, public services)
- Identifies high-value targets (critical assets, PCI/HIPAA scope, confidential data)
- Finds shortest paths using NetworkX algorithms
- Rates threat level based on CVSS scores
- Calculates exploitability (0-100%) based on path length and vulnerabilities

#### Detect Privilege Escalation

Identify opportunities for attackers to escalate privileges:

```bash
# Find privilege escalation paths
threat-radar graph privilege-escalation graph.graphml

# Limit results and save output
threat-radar graph privilege-escalation graph.graphml \
  --max-paths 20 \
  -o privilege-escalation.json

# Shows escalation from:
# - DMZ → Internal zones
# - Public → Trusted zones
# - User → Admin/Root privileges
```

**Output includes:**
- Source and target privilege levels
- Difficulty rating (easy/medium/hard)
- CVEs that enable escalation
- Mitigation recommendations
- Step-by-step attack path

#### Identify Lateral Movement

Find lateral movement opportunities within the infrastructure:

```bash
# Identify lateral movement opportunities
threat-radar graph lateral-movement graph.graphml

# Customize search parameters
threat-radar graph lateral-movement graph.graphml \
  --max-opportunities 30 \
  -o lateral-movement.json

# Identifies movement between assets in:
# - Same network zones
# - Same privilege levels
# - Connected systems
```

**Output includes:**
- Source and target assets
- Movement type (network/credential/vulnerability)
- Detection difficulty (easy/medium/hard)
- Network access requirements
- Prerequisites for successful movement

#### Comprehensive Attack Surface Analysis

Combine all attack path analysis into a complete security assessment:

```bash
# Full attack surface analysis
threat-radar graph attack-surface graph.graphml

# Comprehensive analysis with custom limits
threat-radar graph attack-surface graph.graphml \
  --max-paths 50 \
  -o attack-surface.json

# Provides:
# - Total risk score (0-100)
# - All attack paths
# - Privilege escalation opportunities
# - Lateral movement opportunities
# - Security recommendations
```

**Analysis includes:**
- Overall risk score calculation
- Threat distribution (critical/high/medium/low counts)
- Entry points and high-value targets inventory
- Comprehensive security recommendations
- Prioritized remediation guidance

### Attack Path Analysis Workflows

#### Complete Infrastructure Security Assessment

```bash
#!/bin/bash
# complete-attack-analysis.sh

# 1. Build environment graph with vulnerability data
threat-radar env build-graph production-env.json \
  --merge-scan scan-results-1.json \
  --merge-scan scan-results-2.json \
  -o complete-graph.graphml

# 2. Analyze all attack vectors
threat-radar graph attack-surface complete-graph.graphml \
  -o attack-surface.json

# 3. Find critical attack paths
threat-radar graph attack-paths complete-graph.graphml \
  --max-paths 50 \
  -o critical-paths.json

# 4. Detect privilege escalation opportunities
threat-radar graph privilege-escalation complete-graph.graphml \
  --max-paths 20 \
  -o privesc.json

# 5. Identify lateral movement risks
threat-radar graph lateral-movement complete-graph.graphml \
  --max-opportunities 30 \
  -o lateral.json

# 6. Generate comprehensive report
echo "Attack Surface Analysis Complete:"
jq -r '.total_risk_score' attack-surface.json
jq -r '.recommendations[]' attack-surface.json
```

#### Red Team Attack Path Simulation

```bash
#!/bin/bash
# simulate-attack-paths.sh - Simulate attack scenarios

GRAPH="production-graph.graphml"

# Find all critical-severity attack paths
threat-radar graph attack-paths $GRAPH -o paths.json

# Extract critical paths
CRITICAL=$(jq -r '.attack_paths[] | select(.threat_level=="critical") | .path_id' paths.json)

echo "CRITICAL ATTACK PATHS FOUND:"
echo "$CRITICAL"

# For each critical path, generate detailed analysis
for path_id in $CRITICAL; do
  echo "Analyzing path: $path_id"

  # Extract path details
  jq ".attack_paths[] | select(.path_id==\"$path_id\")" paths.json > path_${path_id}.json

  # Show attack steps
  echo "  Steps:"
  jq -r '.steps[] | "    - \(.description) [\(.type)]"' path_${path_id}.json

  # Show exploitable CVEs
  echo "  CVEs:"
  jq -r '.steps[].vulnerabilities[]?' path_${path_id}.json | sort -u
done
```

#### Continuous Attack Surface Monitoring

```bash
#!/bin/bash
# continuous-monitoring.sh - Track attack surface changes

BASELINE="baseline-attack-surface.json"
CURRENT="current-attack-surface.json"

# Scan current state
threat-radar cve scan-image production:latest --auto-save -o scan.json
threat-radar graph build scan.json -o graph.graphml
threat-radar graph attack-surface graph.graphml -o $CURRENT

# Compare with baseline
BASELINE_RISK=$(jq -r '.total_risk_score' $BASELINE)
CURRENT_RISK=$(jq -r '.total_risk_score' $CURRENT)

echo "Risk Score Comparison:"
echo "  Baseline: $BASELINE_RISK"
echo "  Current:  $CURRENT_RISK"

# Calculate delta
DELTA=$(echo "$CURRENT_RISK - $BASELINE_RISK" | bc)

if (( $(echo "$DELTA > 5.0" | bc -l) )); then
  echo "⚠️  ALERT: Risk score increased by $DELTA points!"

  # Find new attack paths
  comm -13 \
    <(jq -r '.attack_paths[].path_id' $BASELINE | sort) \
    <(jq -r '.attack_paths[].path_id' $CURRENT | sort) \
    > new-paths.txt

  echo "New attack paths detected:"
  cat new-paths.txt

  # Send alert
  send_security_alert "Attack surface increased: +$DELTA risk points"
else
  echo "✅ Attack surface stable or improved"
fi
```

#### Integration with Environment Business Context

Attack path analysis integrates with environment configuration for business-aware risk assessment:

```bash
#!/bin/bash
# business-context-attack-analysis.sh

ENV_FILE="production-environment.json"

# 1. Build graph with environment context
threat-radar env build-graph $ENV_FILE \
  --merge-scan scan1.json \
  --merge-scan scan2.json \
  -o context-graph.graphml

# 2. Find attack paths to critical business assets
threat-radar graph attack-paths context-graph.graphml -o paths.json

# 3. Filter paths targeting PCI-scoped assets
jq '.attack_paths[] | select(.target | contains("asset-payment"))' paths.json \
  > pci-attack-paths.json

# 4. Generate business impact report
echo "PCI-Scoped Attack Paths:"
jq -r '.[] | "Path \(.path_id): \(.threat_level) - CVSS \(.total_cvss)"' \
  pci-attack-paths.json

# 5. Calculate compliance risk
PCI_PATHS=$(jq '. | length' pci-attack-paths.json)
if [ "$PCI_PATHS" -gt 0 ]; then
  echo "⚠️  COMPLIANCE RISK: $PCI_PATHS attack paths to PCI-scoped assets"
  exit 1
fi
```

### Attack Path Architecture

The attack path discovery system uses advanced graph algorithms to model attack scenarios:

**Key Components:**
- **Entry Point Detection**: Identifies internet-facing assets, DMZ zones, and public services
- **Target Identification**: Finds critical assets based on business context, compliance scope, and data sensitivity
- **Path Finding**: Uses NetworkX shortest path algorithms (Dijkstra, BFS)
- **Threat Modeling**: Classifies attack steps (entry, exploit, privilege escalation, lateral movement, target access)
- **Risk Calculation**: Combines CVSS scores, path length, and exploitability for threat levels

**Attack Step Types:**
- **ENTRY_POINT**: Initial access via exposed service
- **EXPLOIT_VULNERABILITY**: Exploitation of CVEs
- **PRIVILEGE_ESCALATION**: Elevation from low to high privilege
- **LATERAL_MOVEMENT**: Movement between assets in same zone
- **TARGET_ACCESS**: Final access to high-value target

**Integration Points:**
- Works with environment configuration for business context
- Uses vulnerability data from CVE scans
- Leverages graph topology for relationship analysis
- Integrates with AI for risk assessment and recommendations

### Future Enhancements (Sprint 3+)

- **Neo4j Support**: Migrate to Neo4j for production-scale deployments
- **Container Dependencies**: Auto-detect Docker Compose/orchestration dependencies
- **Graph Visualization**: Built-in graph rendering (matplotlib/graphviz) of attack paths
- **Attack Simulation**: Interactive "what-if" attack scenario modeling
- **Remediation Impact**: Predict attack surface reduction before applying patches
- **ML-based Path Scoring**: Machine learning for attack path likelihood estimation

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
See `examples/10_attack_path_discovery/sample-environment.json` for a comprehensive example with:
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
- All tests can run independently without external dependencies (except Docker tests)

### Dependencies

**Core Python dependencies:**
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

## Interactive Graph Visualization

### Overview

Threat Radar provides powerful interactive visualization capabilities for vulnerability graphs, attack paths, and network topology. Visualizations are web-based (Plotly), interactive, and can be exported to multiple formats.

**Key Features:**
- **Interactive Exploration**: Zoom, pan, hover for details, click to explore
- **Multiple Layouts**: Spring, hierarchical, circular, spectral algorithms
- **Attack Path Highlighting**: Visual representation of attack routes with threat levels
- **Network Topology Views**: Security zones, compliance scope overlays
- **Advanced Filtering**: Focus on specific severities, packages, zones, or CVEs
- **Multi-Format Export**: HTML, PNG, SVG, PDF, JSON, DOT, GEXF, Cytoscape

### Installation

Visualization features require Plotly:

```bash
# Install visualization dependencies
pip install plotly kaleido

# Or use requirements.txt (already includes visualization libs)
pip install -r requirements.txt
```

### Visualization Commands Reference

#### Basic Graph Visualization

Create interactive vulnerability graph visualizations:

```bash
# Create basic interactive graph
threat-radar visualize graph graph.graphml -o visualization.html

# Open visualization in browser automatically
threat-radar visualize graph graph.graphml -o viz.html --open

# Use different layout algorithm
threat-radar visualize graph graph.graphml -o viz.html \
  --layout hierarchical

# Color by severity instead of node type
threat-radar visualize graph graph.graphml -o viz.html \
  --color-by severity

# Create 3D visualization
threat-radar visualize graph graph.graphml -o viz.html --3d

# Custom dimensions
threat-radar visualize graph graph.graphml -o viz.html \
  --width 1600 --height 1000

# Hide node labels for cleaner view
threat-radar visualize graph graph.graphml -o viz.html --no-labels
```

**Layout algorithms:**
- `spring` - Force-directed layout (default, good for general graphs)
- `hierarchical` - Layered layout (great for vulnerability chains)
- `kamada_kawai` - Energy-based layout (balanced node distribution)
- `circular` - Circular layout (shows connections clearly)
- `spectral` - Spectral layout (based on graph eigenvalues)

**Color schemes:**
- `node_type` - Color by node type (container, package, vulnerability)
- `severity` - Color by vulnerability severity

#### Attack Path Visualization

Visualize attack paths with highlighted routes:

```bash
# Visualize attack paths from graph analysis
threat-radar visualize attack-paths graph.graphml -o attack-paths.html

# Use pre-calculated attack paths JSON
threat-radar visualize attack-paths graph.graphml -o paths.html \
  --paths attack-paths.json

# Show only top 10 most critical paths
threat-radar visualize attack-paths graph.graphml -o paths.html \
  --max-paths 10

# Hierarchical layout for clearer attack flows
threat-radar visualize attack-paths graph.graphml -o paths.html \
  --layout hierarchical

# Custom dimensions for presentation
threat-radar visualize attack-paths graph.graphml -o paths.html \
  --width 1920 --height 1080 --open
```

**Attack path features:**
- Threat level color-coding (critical: red, high: orange, medium: yellow, low: blue)
- Step-by-step attack progression visualization
- Hover for detailed CVE information
- Entry points and targets highlighted
- Exploitability and CVSS scores displayed

#### Network Topology Visualization

Visualize network topology with security context:

```bash
# Basic topology visualization
threat-radar visualize topology graph.graphml -o topology.html

# Security zones view
threat-radar visualize topology graph.graphml -o zones.html \
  --view zones

# Compliance scope view
threat-radar visualize topology graph.graphml -o compliance.html \
  --view compliance

# Specific compliance type (PCI-DSS)
threat-radar visualize topology graph.graphml -o pci.html \
  --view compliance --compliance pci

# Color by criticality
threat-radar visualize topology graph.graphml -o topology.html \
  --color-by criticality

# Color by compliance scope
threat-radar visualize topology graph.graphml -o topology.html \
  --color-by compliance
```

**View types:**
- `topology` - Full network topology with all security context
- `zones` - Focus on security zone boundaries and segregation
- `compliance` - Highlight compliance scope (PCI, HIPAA, SOX, GDPR)

**Color schemes:**
- `zone` - Color by security zone (DMZ, internal, trusted, etc.)
- `criticality` - Color by asset criticality (critical, high, medium, low)
- `compliance` - Color by compliance scope

#### Filtered Visualization

Apply filters to focus on specific graph subsets:

```bash
# Filter by severity (show only HIGH+ vulnerabilities)
threat-radar visualize filter graph.graphml -o filtered.html \
  --type severity --value high

# Filter by node type (show only vulnerabilities and packages)
threat-radar visualize filter graph.graphml -o filtered.html \
  --type node_type --values vulnerability package

# Filter by specific CVE
threat-radar visualize filter graph.graphml -o filtered.html \
  --type cve --values CVE-2023-1234 CVE-2023-5678

# Filter by package name
threat-radar visualize filter graph.graphml -o filtered.html \
  --type package --values openssl curl

# Filter by security zone
threat-radar visualize filter graph.graphml -o filtered.html \
  --type zone --values dmz internal

# Filter by criticality
threat-radar visualize filter graph.graphml -o filtered.html \
  --type criticality --value critical

# Filter by compliance scope
threat-radar visualize filter graph.graphml -o filtered.html \
  --type compliance --values pci hipaa

# Filter internet-facing assets only
threat-radar visualize filter graph.graphml -o filtered.html \
  --type internet_facing

# Search for specific terms
threat-radar visualize filter graph.graphml -o filtered.html \
  --type search --value "openssl"

# Exclude related nodes (show only filtered nodes)
threat-radar visualize filter graph.graphml -o filtered.html \
  --type severity --value critical --no-related
```

**Filter types:**
- `severity` - Filter by vulnerability severity
- `node_type` - Filter by node type(s)
- `cve` - Filter by specific CVE ID(s)
- `package` - Filter by package name(s)
- `zone` - Filter by security zone(s)
- `criticality` - Filter by asset criticality
- `compliance` - Filter by compliance scope(s)
- `internet_facing` - Show only internet-facing assets
- `search` - Search node properties

#### Export Multiple Formats

Export visualizations to various formats:

```bash
# Export as HTML only
threat-radar visualize export graph.graphml -o viz \
  --format html

# Export as PNG image
threat-radar visualize export graph.graphml -o viz \
  --format png

# Export as high-resolution SVG
threat-radar visualize export graph.graphml -o viz \
  --format svg

# Export as PDF for reports
threat-radar visualize export graph.graphml -o viz \
  --format pdf

# Export as JSON for web applications
threat-radar visualize export graph.graphml -o viz \
  --format json

# Export as DOT for Graphviz
threat-radar visualize export graph.graphml -o viz \
  --format dot

# Export as Cytoscape.js format
threat-radar visualize export graph.graphml -o viz \
  --format cytoscape

# Export as GEXF for Gephi
threat-radar visualize export graph.graphml -o viz \
  --format gexf

# Export multiple formats at once
threat-radar visualize export graph.graphml -o viz \
  --format html --format png --format json

# Custom layout for exported visualizations
threat-radar visualize export graph.graphml -o viz \
  --format html --format png --layout hierarchical
```

**Export formats:**
- `html` - Interactive web visualization (standalone, no dependencies)
- `png` - Static PNG image (requires kaleido)
- `svg` - Scalable vector graphics (requires kaleido)
- `pdf` - PDF document (requires kaleido)
- `json` - JSON graph data with positions (for custom web apps)
- `dot` - Graphviz DOT format (requires pydot)
- `cytoscape` - Cytoscape.js JSON format
- `gexf` - GEXF format for Gephi

#### View Filter Statistics

See available filter values before filtering:

```bash
# Show all available filter values
threat-radar visualize stats graph.graphml
```

**Output includes:**
- Total nodes and edges
- Node type counts
- Severity distribution
- Security zones list
- Criticality levels
- Compliance scope counts
- Internet-facing asset count

### Complete Visualization Workflows

#### Security Analysis Workflow

```bash
#!/bin/bash
# complete-viz-workflow.sh

IMAGE="myapp:production"

# 1. Scan image for vulnerabilities
threat-radar cve scan-image $IMAGE --auto-save -o scan.json

# 2. Build vulnerability graph
threat-radar graph build scan.json --auto-save -o vuln.graphml

# 3. Create basic interactive visualization
threat-radar visualize graph vuln.graphml -o viz-overview.html \
  --layout hierarchical --open

# 4. Analyze attack paths
threat-radar graph attack-paths vuln.graphml \
  --max-paths 20 -o attack-paths.json

# 5. Visualize attack paths
threat-radar visualize attack-paths vuln.graphml -o viz-attack-paths.html \
  --paths attack-paths.json --max-paths 10

# 6. Create filtered view of critical issues
threat-radar visualize filter vuln.graphml -o viz-critical.html \
  --type severity --value critical

# 7. Export to multiple formats for reporting
threat-radar visualize export vuln.graphml -o reports/vuln-graph \
  --format html --format png --format pdf

echo "✅ Visualization workflow complete!"
echo "   - Overview: viz-overview.html"
echo "   - Attack Paths: viz-attack-paths.html"
echo "   - Critical Issues: viz-critical.html"
echo "   - Reports: reports/vuln-graph.*"
```

#### Environment Topology Workflow

```bash
#!/bin/bash
# topology-viz-workflow.sh

ENV_FILE="production-environment.json"

# 1. Build environment graph with vulnerability data
threat-radar env build-graph $ENV_FILE \
  --merge-scan scan1.json \
  --merge-scan scan2.json \
  --auto-save -o env-graph.graphml

# 2. Create full topology view
threat-radar visualize topology env-graph.graphml -o topology-full.html \
  --view topology --color-by zone

# 3. Create security zones view
threat-radar visualize topology env-graph.graphml -o topology-zones.html \
  --view zones

# 4. Create compliance scope view (PCI-DSS)
threat-radar visualize topology env-graph.graphml -o topology-pci.html \
  --view compliance --compliance pci

# 5. Filter to show only internet-facing assets
threat-radar visualize filter env-graph.graphml -o topology-external.html \
  --type internet_facing

# 6. Analyze attack paths in environment
threat-radar graph attack-paths env-graph.graphml \
  --max-paths 50 -o env-attack-paths.json

threat-radar visualize attack-paths env-graph.graphml \
  -o topology-attacks.html --paths env-attack-paths.json

echo "✅ Topology visualization complete!"
```

#### Compliance Reporting Workflow

```bash
#!/bin/bash
# compliance-viz-workflow.sh

GRAPH_FILE="production-graph.graphml"

# Show filter statistics
threat-radar visualize stats $GRAPH_FILE

# Create PCI-DSS compliance view
threat-radar visualize topology $GRAPH_FILE -o compliance-pci.html \
  --view compliance --compliance pci

threat-radar visualize filter $GRAPH_FILE -o compliance-pci-critical.html \
  --type compliance --values pci \
  | threat-radar visualize filter - -o compliance-pci-critical.html \
    --type severity --value critical

# Create HIPAA compliance view
threat-radar visualize topology $GRAPH_FILE -o compliance-hipaa.html \
  --view compliance --compliance hipaa

# Export compliance reports
for compliance in pci hipaa sox gdpr; do
  threat-radar visualize export $GRAPH_FILE \
    -o reports/compliance-${compliance} \
    --format html --format pdf
done

echo "✅ Compliance visualizations ready!"
```

### Visualization Architecture

#### Core Components

The visualization system is built on:
- **Plotly** - Interactive web-based visualizations
- **NetworkX** - Graph layout algorithms
- **Rich** - CLI output formatting

#### Python API Usage

Use visualization programmatically:

```python
from threat_radar.graph import NetworkXClient
from threat_radar.visualization import (
    NetworkGraphVisualizer,
    AttackPathVisualizer,
    NetworkTopologyVisualizer,
    GraphFilter,
    GraphExporter,
)

# Load graph
client = NetworkXClient()
client.load("graph.graphml")

# Create basic visualization
visualizer = NetworkGraphVisualizer(client)
fig = visualizer.visualize(
    layout="hierarchical",
    title="My Vulnerability Graph",
    width=1400,
    height=900,
    color_by="severity",
)

# Save as HTML
visualizer.save_html(fig, "output.html", auto_open=True)

# Filter graph
graph_filter = GraphFilter(client)
filtered_client = graph_filter.filter_by_severity("high", include_related=True)

# Visualize filtered graph
filtered_viz = NetworkGraphVisualizer(filtered_client)
filtered_fig = filtered_viz.visualize(layout="spring")

# Export to multiple formats
exporter = GraphExporter(client)
outputs = exporter.export_all_formats(
    fig=fig,
    base_path="my-viz",
    formats=["html", "png", "json"],
)

print(f"Exported to: {outputs}")
```

#### Attack Path Visualization API

```python
from threat_radar.visualization import AttackPathVisualizer
from threat_radar.graph import GraphAnalyzer

# Load graph
client = NetworkXClient()
client.load("graph.graphml")

# Find attack paths
analyzer = GraphAnalyzer(client)
attack_paths = analyzer.find_shortest_attack_paths(max_paths=20)

# Visualize attack paths
path_visualizer = AttackPathVisualizer(client)

# Multiple paths
fig = path_visualizer.visualize_attack_paths(
    attack_paths=attack_paths,
    layout="hierarchical",
    max_paths_display=10,
)

# Single path detail
single_fig = path_visualizer.visualize_single_path(
    attack_path=attack_paths[0],
    show_step_details=True,
)

path_visualizer.save_html(fig, "attack-paths.html")
```

#### Network Topology Visualization API

```python
from threat_radar.visualization import NetworkTopologyVisualizer

# Load graph with environment data
client = NetworkXClient()
client.load("environment-graph.graphml")

# Create topology visualizer
topo_viz = NetworkTopologyVisualizer(client)

# Full topology view
fig = topo_viz.visualize_topology(
    layout="hierarchical",
    color_by="zone",
    show_zones=True,
    show_compliance=True,
)

# Security zones view
zones_fig = topo_viz.visualize_security_zones()

# Compliance scope view
compliance_fig = topo_viz.visualize_compliance_scope(
    compliance_type="pci",
)

topo_viz.save_html(fig, "topology.html")
```

### Troubleshooting Visualizations

#### Plotly Not Installed

```bash
# Error: "Plotly is required for visualization"

# Solution: Install plotly
pip install plotly

# For image export support
pip install kaleido
```

#### Large Graphs Performance

For graphs with thousands of nodes:

```bash
# Use filtering to reduce graph size
threat-radar visualize filter graph.graphml -o filtered.html \
  --type severity --value high --no-related

# Or use simpler layout algorithms
threat-radar visualize graph graph.graphml -o viz.html \
  --layout circular --no-labels

# Export as JSON for custom web rendering
threat-radar visualize export graph.graphml -o data.json \
  --format json
```

#### Image Export Fails

```bash
# Error: "Image export failed" or "kaleido not found"

# Solution: Install kaleido
pip install kaleido

# If still failing, try reinstalling
pip uninstall kaleido
pip install kaleido --force-reinstall
```

---

## Documentation Resources

### User Documentation
- **[INSTALLATION.md](docs/INSTALLATION.md)** - Complete installation guide for all platforms (macOS, Linux, Windows)
- **[docs/CLI_FEATURES.md](docs/CLI_FEATURES.md)** - Comprehensive CLI features guide (global options, configuration, filtering, output formats)
- **[CHANGELOG.md](CHANGELOG.md)** - Version history and release notes

### Developer Documentation
- **[docs/API.md](docs/API.md)** - Complete Python API reference for programmatic usage
- **[PUBLISHING.md](docs/PUBLISHING.md)** - PyPI publishing and release workflow guide
- **[threat-radar.config.example.json](threat-radar.config.example.json)** - Example configuration file template

### Additional Resources
- **[README.md](README.md)** - Project overview and quick start
- **[examples/TROUBLESHOOTING.md](examples/TROUBLESHOOTING.md)** - Common issues and solutions
- **[.env.example](.env.example)** - Environment variables template
