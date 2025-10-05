# Threat Radar Examples

This directory contains comprehensive examples demonstrating the Threat Radar vulnerability management platform.

## Prerequisites

1. **Install Threat Radar:**
   ```bash
   pip install -e .
   ```

2. **Docker (for container examples):**
   - Ensure Docker daemon is running
   - Pull required images first: `docker pull alpine:3.18`

3. **NVD API Key (optional but recommended):**
   ```bash
   # Get a free API key from: https://nvd.nist.gov/developers/request-an-api-key
   echo "NVD_API_KEY=your_key_here" >> .env
   ```

## Examples Overview

### 1. Basic Docker Analysis

**File:** `docker_usage.py`

Demonstrates basic Docker container analysis:
- Pulling and analyzing images
- Extracting installed packages
- Detecting Linux distributions
- Exporting analysis to JSON

**Run:**
```bash
python examples/docker_usage.py
```

### 2. Advanced Docker Features

**File:** `docker_advanced.py`

Advanced Docker integration features:
- Batch image analysis
- Comparing images
- Security-focused analysis
- Package filtering and search

**Run:**
```bash
python examples/docker_advanced.py
```

### 3. Python SBOM Generation

**File:** `python_sbom_example.py`

Python package SBOM generation:
- Extracting pip packages from containers
- Generating CycloneDX SBOM
- Multiple output formats (JSON, CSV, TXT)

**Run:**
```bash
python examples/python_sbom_example.py
```

### 4. NVD API Basics

**File:** `nvd_basic_usage.py`

NVD REST API integration:
- Fetching specific CVEs by ID
- Searching CVEs by keyword, CPE, severity
- Rate limiting demonstration
- Local caching behavior
- API key usage

**Run:**
```bash
python examples/nvd_basic_usage.py
```

**Examples:**
- Fetch Log4Shell: `CVE-2021-44228`
- Search by keyword: `openssl`, `log4j`
- Filter by severity: `CRITICAL`, `HIGH`
- Recent CVEs from last N days

### 5. CVE Database Management

**File:** `cve_database_usage.py`

Local CVE database operations:
- Initializing SQLite database
- Incremental updates from NVD
- Searching local database (fast)
- Database statistics
- Manual CVE storage

**Run:**
```bash
python examples/cve_database_usage.py
```

**Database Location:** `~/.threat_radar/cve.db`

### 6. CVE Matching & Algorithms

**File:** `cve_matching_example.py`

CVE matching algorithms:
- Semantic version comparison
- Version range checking
- Package name fuzzy matching
- Confidence scoring
- Bulk package matching

**Run:**
```bash
python examples/cve_matching_example.py
```

**Key Features:**
- Handles version formats: `1.2.3`, `v2.0.0-beta`, `3.1`
- Fuzzy matching: `libssl` ↔ `openssl`
- Confidence thresholds: 0.5 - 1.0
- Known package mappings

### 7. Complete Vulnerability Scanning

**File:** `docker_vulnerability_scan.py`

End-to-end vulnerability scanning workflow:
- Analyzing Docker images
- Matching packages against CVE database
- Generating JSON reports
- Comparing images
- Filtering by severity
- Continuous monitoring simulation

**Run:**
```bash
python examples/docker_vulnerability_scan.py
```

**Generates:** Detailed vulnerability reports in JSON format

## Quick Start Examples

### Scan a Docker Image for Vulnerabilities

```python
from threat_radar.core.container_analyzer import ContainerAnalyzer
from threat_radar.core.cve_database import CVEDatabase
from threat_radar.core.cve_matcher import CVEMatcher

# Analyze image
analyzer = ContainerAnalyzer()
analysis = analyzer.analyze_container("alpine:3.18")
analyzer.close()

# Update CVE database
db = CVEDatabase()
db.update_from_nvd(days=30)
cves = db.search_cves(limit=1000)

# Match vulnerabilities
matcher = CVEMatcher(min_confidence=0.7)
matches = matcher.bulk_match_packages(analysis.packages, cves)

# Display results
for pkg_name, pkg_matches in matches.items():
    print(f"{pkg_name}: {len(pkg_matches)} vulnerabilities")

db.close()
```

### Fetch a Specific CVE

```python
from threat_radar.core.nvd_client import NVDClient

client = NVDClient()
cve = client.get_cve_by_id("CVE-2021-44228")  # Log4Shell

print(f"{cve.cve_id}: {cve.severity} (CVSS: {cve.cvss_score})")
print(f"{cve.description}")

client.close()
```

### Search Recent CVEs

```python
from threat_radar.core.nvd_client import NVDClient

client = NVDClient()
cves = client.search_cves(
    keyword="openssl",
    cvss_severity="CRITICAL",
    results_per_page=10
)

for cve in cves:
    print(f"{cve.cve_id} - CVSS: {cve.cvss_score}")

client.close()
```

## CLI Usage Examples

### Update CVE Database

```bash
threat-radar cve update --days 30
```

### Scan Docker Image

```bash
threat-radar cve scan-image ubuntu:22.04 --confidence 0.7 -o report.json
```

### Search CVEs

```bash
# Search NVD API
threat-radar cve search --keyword log4j --severity CRITICAL

# Search local database (faster)
threat-radar cve db-search --severity HIGH --min-cvss 7.0
```

### Get Specific CVE

```bash
threat-radar cve get CVE-2021-44228 CVE-2021-45046 -o cves.json
```

### Database Statistics

```bash
threat-radar cve stats
```

### Clear Cache

```bash
threat-radar cve clear-cache --older-than 7 --yes
```

## File Hashing Examples

**File:** `hash_usage.py`

Demonstrates file integrity verification:
- SHA-256, MD5, SHA-1 hashing
- Built-in vs cryptographic hashing
- Binary and text file handling

**Run:**
```bash
python examples/hash_usage.py
```

## Environment Variables

Create a `.env` file with:

```bash
# NVD API Key (optional, increases rate limits from 5 to 50 req/30s)
NVD_API_KEY=your_nvd_api_key_here

# GitHub Access Token (for GitHub integration)
GITHUB_ACCESS_TOKEN=your_github_token_here
```

## Rate Limits

**Without API Key:**
- 5 requests per 30 seconds
- Recommended for testing only

**With NVD API Key:**
- 50 requests per 30 seconds
- Get free key at: https://nvd.nist.gov/developers/request-an-api-key

## Output Files

Examples may generate:

- `vulnerability_report_*.json` - Vulnerability scan reports
- `alpine_analysis.json` - Container analysis results
- `sbom.json` - Software Bill of Materials
- `~/.threat_radar/cve.db` - Local CVE database
- `~/.threat_radar/cache/` - Cached CVE data

## Tips

1. **First Run:** Examples may be slow initially due to:
   - Docker image pulls
   - CVE database population
   - NVD API rate limits

2. **Subsequent Runs:** Much faster due to:
   - Local caching
   - Database storage
   - Docker image cache

3. **Offline Mode:** After initial population, most features work offline using local database

4. **Performance:** Use local database search (`db-search`) instead of API search for better performance

5. **Accuracy:** Higher confidence thresholds (0.8+) reduce false positives but may miss some matches

## Troubleshooting

**Docker connection errors:**
```bash
# Ensure Docker is running
docker ps

# Check Docker access
docker info
```

**NVD API rate limits:**
```bash
# Get an API key or wait between requests
# The client automatically handles rate limiting
```

**Database locked:**
```bash
# Close any running threat-radar processes
# Delete and reinitialize: rm ~/.threat_radar/cve.db
```

**Import errors:**
```bash
# Ensure package is installed
pip install -e .

# Or run from project root
PYTHONPATH=. python examples/nvd_basic_usage.py
```

## Next Steps

1. Review the examples in order
2. Modify examples for your use case
3. Explore the CLI commands
4. Build custom scanning workflows
5. Integrate into CI/CD pipelines

## Documentation

- **Main README:** `/README.md`
- **CLAUDE.md:** `/CLAUDE.md` - Development guide
- **API Docs:** Run `threat-radar --help`

## Contributing

Examples are welcome! Please ensure:
- Clear documentation
- Error handling
- Example output shown in comments
- Compatible with existing structure
