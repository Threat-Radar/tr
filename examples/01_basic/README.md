# Basic Examples

Fundamental operations to get started with Threat Radar. Start here if you're new to the platform.

## Examples Overview

| Example | What It Does | Time | Prerequisites |
|---------|--------------|------|---------------|
| `docker_usage.py` | Analyze Docker images, extract packages | ~2 min | Docker running |
| `hash_usage.py` | Generate file hashes (SHA-256, MD5, SHA-1) | <1 min | None |
| `nvd_basic_usage.py` | Fetch CVEs from NVD *(historical)* | ~3 min | Internet |
| `cve_database_usage.py` | Local CVE database *(historical)* | ~5 min | Internet |

## Quick Start

```bash
# Run all basic examples
python docker_usage.py
python hash_usage.py
```

## Example Details

### 1. Docker Container Analysis ⭐ RECOMMENDED

**File:** `docker_usage.py`

Learn Docker image analysis and package extraction.

```bash
python docker_usage.py
```

**What you'll learn:**
- Pull and analyze Docker images
- Extract installed packages (APK, APT, YUM)
- Detect Linux distributions
- Export analysis to JSON

### 2. File Hashing

**File:** `hash_usage.py`

Generate cryptographic hashes for file integrity verification.

```bash
python hash_usage.py
```

**What you'll learn:**
- SHA-256, MD5, SHA-1 hashing
- Binary vs text file handling
- Integrity verification

### 3. NVD API Basics *(Historical)*

**File:** `nvd_basic_usage.py`

Fetch CVE data from the National Vulnerability Database.

**Note:** This example demonstrates the legacy NVD-based approach. For new projects, use Grype-based scanning via CLI:
```bash
threat-radar cve scan-image alpine:3.18
```

### 4. CVE Database Operations *(Historical)*

**File:** `cve_database_usage.py`

Work with local CVE database for offline queries.

**Note:** This is legacy functionality. Modern workflow uses Grype's local database automatically.

## Next Steps

After completing these examples:

**For Modern Workflows:**
- ✅ Use `threat-radar cve scan-image` for vulnerability scanning (Grype-powered)
- ✅ Use `threat-radar sbom docker` for SBOM generation (Syft-powered)
- ✅ See [../README.md](../README.md) for complete CLI reference

**For Python API Examples:**
- → **[02_advanced/](../02_advanced/)** - Advanced Docker features and SBOM generation
- → **[05_reporting/](../05_reporting/)** - Comprehensive reporting with AI

## Documentation

- **[Main Examples Guide](../README.md)** - Complete examples overview
- **[CLI Reference](../../CLAUDE.md)** - Full command documentation
- **[Troubleshooting](../TROUBLESHOOTING.md)** - Common issues

---

**Quick command:** `python docker_usage.py && python hash_usage.py`
