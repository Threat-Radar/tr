# Advanced Examples

Advanced features for Docker analysis and SBOM generation. These examples demonstrate deeper integration capabilities.

## Examples Overview

| Example | What It Does | Time | Best For |
|---------|--------------|------|----------|
| `docker_advanced.py` | Batch analysis, image comparison | ~5 min | Production workflows |
| `syft_sbom_example.py` | Comprehensive SBOM with Syft | ~4 min | Compliance, SBOM standards |
| `python_sbom_example.py` | Python-specific SBOM | ~2 min | Python projects |
| `docker_cli_examples.sh` | CLI workflow automation | ~3 min | CI/CD integration |

## Quick Start

```bash
# Generate SBOM with Syft (recommended)
python syft_sbom_example.py

# Advanced Docker analysis
python docker_advanced.py
```

## Example Details

### 1. Syft SBOM Integration ⭐ RECOMMENDED

**File:** `syft_sbom_example.py`

Comprehensive SBOM generation using Syft (industry-standard tool).

```bash
python syft_sbom_example.py
```

**Features:**
- Multiple SBOM formats (CycloneDX, SPDX, Syft JSON)
- Docker image scanning
- Directory and file scanning
- License analysis
- Package comparison
- 13+ ecosystem support (Python, npm, Go, Java, etc.)

**Prerequisites:** Syft installed (`brew install syft`)

**Alternative (CLI):**
```bash
threat-radar sbom docker alpine:3.18 -o sbom.json
threat-radar sbom generate ./my-project -f cyclonedx-json
```

### 2. Advanced Docker Analysis

**File:** `docker_advanced.py`

Advanced Docker image analysis techniques.

```bash
python docker_advanced.py
```

**Features:**
- Batch image analysis
- Image comparison
- Package filtering and search
- Security-focused analysis

**Alternative (CLI):**
```bash
threat-radar docker import-image ubuntu:22.04
threat-radar docker packages alpine:3.18 --limit 20
```

### 3. Python SBOM Generation

**File:** `python_sbom_example.py`

Generate Software Bill of Materials for Python applications.

```bash
python python_sbom_example.py
```

**Features:**
- Extract Python packages from containers
- Generate CycloneDX SBOM format
- Multiple output formats (JSON, CSV, TXT)
- Dependency analysis

**Alternative (CLI):**
```bash
threat-radar docker python-sbom python:3.11 -o sbom.json
```

### 4. CLI Examples

**File:** `docker_cli_examples.sh`

Shell script demonstrating CLI workflows.

```bash
bash docker_cli_examples.sh
```

**Features:**
- Automated scanning workflows
- Batch processing
- Report generation
- CI/CD integration patterns

## Recommended Workflows

### Compare Two Docker Images

**Python API:**
```python
from threat_radar.utils import docker_analyzer

images = ["alpine:3.17", "alpine:3.18"]
for image in images:
    with docker_analyzer() as analyzer:
        analysis = analyzer.import_container(*image.split(':'))
        # Compare results...
```

**CLI (Recommended):**
```bash
threat-radar sbom docker alpine:3.17 -o sbom-3.17.json
threat-radar sbom docker alpine:3.18 -o sbom-3.18.json
threat-radar sbom compare sbom-3.17.json sbom-3.18.json
```

### Generate SBOM for Production

**CLI (Recommended):**
```bash
# Generate SBOM
threat-radar sbom docker myapp:latest -o production-sbom.json --auto-save

# Scan for vulnerabilities
threat-radar cve scan-sbom production-sbom.json -o scan.json

# Generate report
threat-radar report generate scan.json -o report.html -f html
```

## Prerequisites

- Python 3.8+
- Docker daemon running
- **Syft** installed (`brew install syft`) - for `syft_sbom_example.py`
- Completion of [01_basic/](../01_basic/) examples recommended

## Next Steps

After mastering these examples:

**For Vulnerability Scanning:**
- → Use `threat-radar cve scan-image` (Grype-powered)
- → See [../README.md](../README.md) for full CLI reference

**For Python Examples:**
- → **[05_reporting/](../05_reporting/)** - Comprehensive reporting
- → **[04_testing/](../04_testing/)** - Testing and validation

**For Legacy Workflows:**
- → **[03_vulnerability_scanning/](../03_vulnerability_scanning/)** - Historical NVD-based scanning

## Documentation

- **[Main Examples Guide](../README.md)** - Complete examples overview
- **[SBOM Documentation](../../docs/SBOM_SYFT.md)** - SBOM capabilities
- **[CLI Reference](../../CLAUDE.md)** - Full command documentation

---

**Quick command:** `python syft_sbom_example.py`
