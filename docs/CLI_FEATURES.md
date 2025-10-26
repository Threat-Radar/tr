# Threat Radar CLI Features Guide

Complete guide to advanced CLI options, configuration management, and filtering capabilities.

---

## Table of Contents

1. [Global Options](#global-options)
2. [Configuration File Support](#configuration-file-support)
3. [Verbosity Control](#verbosity-control)
4. [Output Formats](#output-formats)
5. [Filtering Options](#filtering-options)
6. [Configuration Management](#configuration-management)
7. [Environment Variables](#environment-variables)
8. [Examples](#examples)

---

## Global Options

Global options can be applied to any command and affect behavior across the entire CLI.

### Available Global Options

```bash
Options:
  -c, --config PATH        Path to configuration file (JSON format)
  -v, --verbose            Increase verbosity (can be repeated: -v, -vv, -vvv)
  -q, --quiet              Suppress all output except errors
  -f, --output-format TEXT Default output format (table, json, yaml, csv)
  --no-color               Disable colored output
  --no-progress            Disable progress indicators
  --help                   Show help message
```

### Usage Examples

```bash
# Increase verbosity
threat-radar -v cve scan-image alpine:3.18
threat-radar -vv ai analyze scan.json  # More verbose

# Use custom config file
threat-radar --config ./myconfig.json cve scan-image python:3.11

# Quiet mode (errors only)
threat-radar -q sbom generate ./my-app

# No color output (for scripts)
threat-radar --no-color cve scan-image alpine:3.18

# JSON output format
threat-radar -f json sbom docker alpine:3.18
```

---

## Configuration File Support

Threat Radar supports persistent configuration through JSON files.

### Configuration File Locations

Threat Radar searches for configuration files in the following order (first found wins):

1. `./.threat-radar.json` (current directory)
2. `./threat-radar.json` (current directory)
3. `~/.threat-radar/config.json` (user home)
4. `~/.config/threat-radar/config.json` (XDG config)

### Configuration File Structure

```json
{
  "scan": {
    "severity": null,
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

#### Initialize Configuration

```bash
# Create default config file
threat-radar config init

# Create at specific path
threat-radar config init --path ./my-config.json

# Overwrite existing
threat-radar config init --force
```

#### View Configuration

```bash
# Show all configuration
threat-radar config show

# Show specific setting
threat-radar config show scan.severity
threat-radar config show ai.provider
threat-radar config show output.verbosity
```

#### Modify Configuration

```bash
# Set configuration values
threat-radar config set scan.severity HIGH
threat-radar config set ai.provider ollama
threat-radar config set output.verbosity 2
threat-radar config set scan.auto_save true

# Set without saving (temporary)
threat-radar config set output.color false --no-save
```

#### Validate Configuration

```bash
# Validate current config
threat-radar config validate

# Validate specific file
threat-radar config validate ./my-config.json
```

#### Show Config Paths

```bash
# List all config file locations
threat-radar config path
```

---

## Verbosity Control

Control the amount of output and logging information.

### Verbosity Levels

| Level | Flag | Description | Use Case |
|-------|------|-------------|----------|
| 0 | `--quiet` or `-q` | Errors only | Scripts, automation |
| 1 | (default) | Warnings and errors | Normal interactive use |
| 2 | `-v` | Info, warnings, errors | Debugging issues |
| 3 | `-vv` | Debug - everything | Development, troubleshooting |

### Examples

```bash
# Quiet - only errors
threat-radar -q cve scan-image alpine:3.18

# Normal (default)
threat-radar cve scan-image alpine:3.18

# Verbose - show progress and info
threat-radar -v cve scan-image alpine:3.18

# Very verbose - debug logging
threat-radar -vv cve scan-image alpine:3.18

# Extremely verbose - all internal logging
threat-radar -vvv cve scan-image alpine:3.18
```

---

## Output Formats

### Available Formats

1. **table** - Human-readable formatted tables (default for interactive)
2. **json** - Machine-readable JSON output (best for automation)
3. **yaml** - YAML format (human-readable structured data)
4. **csv** - Comma-separated values (spreadsheet compatible)

### Format Examples

#### JSON Output
```bash
threat-radar -f json cve scan-image alpine:3.18
```

Output:
```json
{
  "target": "alpine:3.18",
  "total_vulnerabilities": 5,
  "severity_counts": {
    "high": 2,
    "medium": 3
  },
  "vulnerabilities": [...]
}
```

#### Table Output (Default)
```bash
threat-radar cve scan-image alpine:3.18
```

Output:
```
┌──────────────┬──────────┬─────────────────┬────────────┐
│ CVE ID       │ Severity │ Package         │ Fixed In   │
├──────────────┼──────────┼─────────────────┼────────────┤
│ CVE-2023-xxx │ HIGH     │ openssl@1.1.1   │ 1.1.1w     │
└──────────────┴──────────┴─────────────────┴────────────┘
```

---

## Filtering Options

### CVE Scan Filtering

#### Severity Filtering

```bash
# Show only CRITICAL vulnerabilities
threat-radar cve scan-image alpine:3.18 --severity CRITICAL

# Show HIGH and above
threat-radar cve scan-image alpine:3.18 --severity HIGH

# Show MEDIUM and above
threat-radar cve scan-image alpine:3.18 --severity MEDIUM
```

**Severity levels:** NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL

#### Fixed-Only Filter

```bash
# Show only vulnerabilities with fixes available
threat-radar cve scan-image alpine:3.18 --only-fixed

# Combine with severity
threat-radar cve scan-image alpine:3.18 --severity HIGH --only-fixed
```

#### Fail-On Severity

```bash
# Exit with error if HIGH or above found
threat-radar cve scan-image alpine:3.18 --fail-on HIGH

# Exit with error if any CRITICAL found
threat-radar cve scan-image alpine:3.18 --fail-on CRITICAL
```

### SBOM Filtering

```bash
# Filter by package type
threat-radar sbom components sbom.json --type library

# Filter by language
threat-radar sbom components sbom.json --language python

# Search for specific packages
threat-radar sbom search sbom.json openssl
```

### AI Analysis Filtering

```bash
# Analyze only CRITICAL vulnerabilities
threat-radar ai analyze scan.json --severity critical

# Analyze HIGH and above
threat-radar ai analyze scan.json --severity high
```

---

## Configuration Precedence

Configuration is applied in this order (later overrides earlier):

1. **Default values** (built into code)
2. **Configuration file** (if found)
3. **Environment variables** (if set)
4. **Command-line options** (highest priority)

### Example

```bash
# Config file says: verbosity = 1
# Environment says: THREAT_RADAR_VERBOSITY=2
# Command line says: -vvv (verbosity=3)
# Result: verbosity = 3 (command line wins)
```

---

## Environment Variables

### Scan Configuration

```bash
THREAT_RADAR_SEVERITY=HIGH         # Default severity filter
THREAT_RADAR_AUTO_SAVE=true        # Auto-save scan results
```

### AI Configuration

```bash
AI_PROVIDER=openai                 # AI provider (from .env)
AI_MODEL=gpt-4o                    # AI model (from .env)
```

### Output Configuration

```bash
THREAT_RADAR_VERBOSITY=2           # Verbosity level
THREAT_RADAR_OUTPUT_FORMAT=json    # Output format
```

---

## Examples

### Complete Workflow Examples

#### 1. Quiet Automation Script

```bash
#!/bin/bash
# Use quiet mode, JSON output, auto-save

threat-radar -q -f json \
  cve scan-image myapp:latest \
  --severity CRITICAL \
  --auto-save \
  --fail-on HIGH
```

#### 2. Verbose Debugging

```bash
# Maximum verbosity for troubleshooting
threat-radar -vvv \
  --config ./debug-config.json \
  cve scan-image alpine:3.18
```

#### 3. Custom Configuration

```bash
# Create custom config for project
cat > .threat-radar.json <<EOF
{
  "scan": {
    "severity": "HIGH",
    "auto_save": true,
    "only_fixed": true
  },
  "output": {
    "verbosity": 2,
    "format": "json"
  }
}
EOF

# Use it (automatically detected)
threat-radar cve scan-image myapp:latest
```

#### 4. CI/CD Pipeline

```bash
# GitHub Actions / GitLab CI
threat-radar -q --no-color --no-progress \
  cve scan-image $IMAGE_NAME \
  --severity HIGH \
  --fail-on CRITICAL \
  -o results.json
```

#### 5. Combined Filtering

```bash
# High severity, only fixed, auto-save, cleanup
threat-radar cve scan-image python:3.11 \
  --severity HIGH \
  --only-fixed \
  --auto-save \
  --cleanup
```

### Configuration Templates

#### Minimal (CI/CD)

```json
{
  "output": {
    "verbosity": 0,
    "color": false,
    "progress": false,
    "format": "json"
  },
  "scan": {
    "auto_save": true,
    "cleanup": true
  }
}
```

#### Development

```json
{
  "output": {
    "verbosity": 2,
    "color": true,
    "progress": true,
    "format": "table"
  },
  "scan": {
    "auto_save": true,
    "cleanup": false,
    "severity": "MEDIUM"
  }
}
```

#### Production Security Scan

```json
{
  "scan": {
    "severity": "HIGH",
    "only_fixed": true,
    "auto_save": true
  },
  "ai": {
    "provider": "openai",
    "model": "gpt-4o"
  },
  "report": {
    "level": "detailed",
    "include_executive_summary": true
  }
}
```

---

## Tips and Best Practices

### 1. Use Configuration Files for Teams

```bash
# Commit a project-level config
echo ".threat-radar.json" >> .git
# Team members get consistent behavior
```

### 2. Combine with Environment Variables

```bash
# .env file
AI_PROVIDER=openai
AI_MODEL=gpt-4o

# Config file handles the rest
threat-radar ai analyze scan.json
```

### 3. Use Quiet Mode in Scripts

```bash
# Check exit code instead of parsing output
if threat-radar -q cve scan-image myapp:latest --fail-on HIGH; then
  echo "No high-severity vulnerabilities"
else
  echo "High-severity vulnerabilities found!"
  exit 1
fi
```

### 4. Debug with Verbosity

```bash
# When something doesn't work:
threat-radar -vvv cve scan-image problem:latest
# See all internal logging
```

### 5. Per-Project Configs

```bash
project-a/
  .threat-radar.json    # Strict security settings
project-b/
  .threat-radar.json    # Relaxed development settings
```

---

## Troubleshooting

### Configuration Not Loading

```bash
# Check which config is loaded
threat-radar config path

# Validate config file
threat-radar config validate

# Show current config
threat-radar config show
```

### Output Not Formatted Correctly

```bash
# Disable color for piping
threat-radar --no-color cve scan-image alpine:3.18 > output.txt

# Use JSON for machine parsing
threat-radar -f json cve scan-image alpine:3.18 | jq
```

### Too Much/Too Little Output

```bash
# Adjust verbosity
threat-radar -q ...    # Quiet
threat-radar ...       # Normal
threat-radar -v ...    # Verbose
threat-radar -vv ...   # Very verbose
```

---

## See Also

- **[CLAUDE.md](../CLAUDE.md)** - Complete CLI reference
- **[INSTALLATION.md](../INSTALLATION.md)** - Installation guide
- **[API.md](API.md)** - Python API documentation
- **Configuration Example:** `threat-radar.config.example.json`

---

**Need help?** Run `threat-radar COMMAND --help` for command-specific options.
