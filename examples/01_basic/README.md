# Basic Examples

Start here if you're new to Threat Radar. These examples cover fundamental operations.

## Examples

### 1. Docker Container Analysis
**File:** `docker_usage.py`

Learn how to analyze Docker images and extract package information.

```bash
python docker_usage.py
```

**What you'll learn:**
- Pull and analyze Docker images
- Extract installed packages
- Detect Linux distributions
- Export analysis to JSON

**Time:** ~2 minutes

---

### 2. NVD API Basics
**File:** `nvd_basic_usage.py`

Fetch CVE data from the National Vulnerability Database.

```bash
python nvd_basic_usage.py
```

**What you'll learn:**
- Fetch specific CVEs by ID
- Search by keyword, severity, CPE
- Understand rate limiting
- Use API keys for higher limits

**Time:** ~3 minutes

---

### 3. CVE Database Operations
**File:** `cve_database_usage.py`

Work with the local CVE database for fast offline queries.

```bash
python cve_database_usage.py
```

**What you'll learn:**
- Initialize SQLite database
- Incremental updates from NVD
- Search local database (fast!)
- Get statistics and reports

**Time:** ~5 minutes (first run slower due to database creation)

---

### 4. File Hashing
**File:** `hash_usage.py`

Generate cryptographic hashes for file integrity verification.

```bash
python hash_usage.py
```

**What you'll learn:**
- SHA-256, MD5, SHA-1 hashing
- Binary vs text file handling
- Integrity verification

**Time:** <1 minute

---

## Quick Start

Run all basic examples in sequence:

```bash
# 1. Docker analysis
python docker_usage.py

# 2. Fetch a famous CVE (Shellshock)
python nvd_basic_usage.py

# 3. Build local database
python cve_database_usage.py

# 4. Generate file hashes
python hash_usage.py
```

## Prerequisites

- Docker daemon running (for `docker_usage.py`)
- Internet connection (for NVD API examples)
- Optional: NVD API key in `.env` file

## Next Steps

After completing these examples, move on to:
- **[02_advanced](../02_advanced/)** - Advanced Docker features and SBOM generation
- **[03_vulnerability_scanning](../03_vulnerability_scanning/)** - Complete vulnerability scanning workflows

## Troubleshooting

If you encounter issues, see [TROUBLESHOOTING.md](../TROUBLESHOOTING.md)
