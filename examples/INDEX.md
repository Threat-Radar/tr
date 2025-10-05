# Examples Index

Complete guide to all Threat Radar examples.

## 📚 Quick Reference

| Example | File | Description | Time to Run |
|---------|------|-------------|-------------|
| **CLI Workflows** | [CLI_EXAMPLES.md](CLI_EXAMPLES.md) | Complete CLI command reference | N/A |
| **Basic Docker** | [docker_usage.py](docker_usage.py) | Container analysis basics | ~2 min |
| **Advanced Docker** | [docker_advanced.py](docker_advanced.py) | Batch analysis, comparison | ~5 min |
| **Python SBOM** | [python_sbom_example.py](python_sbom_example.py) | Generate SBOMs | ~2 min |
| **NVD API** | [nvd_basic_usage.py](nvd_basic_usage.py) | Fetch CVEs from NVD | ~3 min |
| **CVE Database** | [cve_database_usage.py](cve_database_usage.py) | Local database operations | ~5 min |
| **CVE Matching** | [cve_matching_example.py](cve_matching_example.py) | Matching algorithms | <1 min |
| **Full Scan** | [docker_vulnerability_scan.py](docker_vulnerability_scan.py) | Complete workflow | ~10 min |
| **File Hashing** | [hash_usage.py](hash_usage.py) | File integrity | <1 min |

## 🎯 By Use Case

### I want to...

#### Analyze Docker Containers
1. **Quick Start:** [docker_usage.py](docker_usage.py) - Basic image analysis
2. **Advanced:** [docker_advanced.py](docker_advanced.py) - Batch processing, comparisons
3. **SBOM:** [python_sbom_example.py](python_sbom_example.py) - Generate Software Bill of Materials

#### Check for Vulnerabilities
1. **Quick Scan:** [CLI_EXAMPLES.md](CLI_EXAMPLES.md#vulnerability-scanning) - CLI commands
2. **Deep Dive:** [docker_vulnerability_scan.py](docker_vulnerability_scan.py) - Full workflow
3. **Understanding Matching:** [cve_matching_example.py](cve_matching_example.py) - How it works

#### Work with CVE Data
1. **Fetch CVEs:** [nvd_basic_usage.py](nvd_basic_usage.py) - NVD API usage
2. **Build Database:** [cve_database_usage.py](cve_database_usage.py) - Local storage
3. **Search & Filter:** [CLI_EXAMPLES.md](CLI_EXAMPLES.md#cve-operations) - Database queries

#### Integrate into CI/CD
1. **CLI Reference:** [CLI_EXAMPLES.md](CLI_EXAMPLES.md#complete-workflows) - Scripts & workflows
2. **GitHub Actions:** [CLI_EXAMPLES.md](CLI_EXAMPLES.md#workflow-4-cicd-integration) - YAML example
3. **Automation:** [docker_vulnerability_scan.py](docker_vulnerability_scan.py) - Example 6

## 📖 Learning Path

### Beginner (Start Here)

**Day 1: Docker Analysis**
```bash
# 1. Basic container analysis
python examples/docker_usage.py

# 2. Try the CLI
threat-radar docker scan alpine:3.18
```

**Day 2: CVE Basics**
```bash
# 1. Fetch a CVE
python examples/nvd_basic_usage.py

# 2. Try CLI
threat-radar cve get CVE-2021-44228
```

**Day 3: Local Database**
```bash
# 1. Learn database operations
python examples/cve_database_usage.py

# 2. Build your database
threat-radar cve update --days 30
```

### Intermediate

**Week 1: Understanding Matching**
```bash
# 1. Learn algorithms
python examples/cve_matching_example.py

# 2. Test with real data
threat-radar cve scan-image ubuntu:22.04
```

**Week 2: Complete Workflows**
```bash
# 1. Full scanning workflow
python examples/docker_vulnerability_scan.py

# 2. Advanced CLI usage
# See CLI_EXAMPLES.md workflows section
```

### Advanced

**Production Integration**
1. Set up continuous monitoring
2. Configure CI/CD pipelines
3. Build custom scanning tools
4. Create automated reports

See: [CLI_EXAMPLES.md - Complete Workflows](CLI_EXAMPLES.md#complete-workflows)

## 🚀 Quick Start Examples

### 1. Scan Your First Image (5 minutes)

```bash
# Install
pip install -e .

# Setup (optional)
echo "NVD_API_KEY=your_key" >> .env

# Update database
threat-radar cve update --days 30

# Scan an image
threat-radar cve scan-image alpine:3.18
```

### 2. Generate SBOM (2 minutes)

```bash
# Python packages
threat-radar docker python-sbom python:3.11 \
  -o sbom.json --format cyclonedx

# View the SBOM
cat sbom.json | jq .
```

### 3. Find Critical CVEs (3 minutes)

```bash
# Update database
threat-radar cve update

# Search critical
threat-radar cve db-search --severity CRITICAL --limit 10

# Get details
threat-radar cve get CVE-2021-44228
```

## 📁 File Descriptions

### Documentation

- **[README.md](README.md)** - Main examples documentation
- **[CLI_EXAMPLES.md](CLI_EXAMPLES.md)** - Complete CLI reference with workflows
- **[INDEX.md](INDEX.md)** - This file - navigation guide

### Python Examples

#### Docker Analysis
- **[docker_usage.py](docker_usage.py)**
  - Pull and analyze images
  - Extract package lists
  - Detect distributions
  - Export to JSON

- **[docker_advanced.py](docker_advanced.py)**
  - Batch image processing
  - Image comparison
  - Package filtering
  - Security analysis

- **[python_sbom_example.py](python_sbom_example.py)**
  - Extract Python packages
  - Generate CycloneDX SBOM
  - Multiple output formats
  - Dependency analysis

#### CVE Management
- **[nvd_basic_usage.py](nvd_basic_usage.py)**
  - Fetch CVEs by ID
  - Search by keyword, CPE, severity
  - Rate limiting demo
  - Caching behavior
  - API key usage

- **[cve_database_usage.py](cve_database_usage.py)**
  - Initialize SQLite database
  - Incremental updates
  - Local search (fast)
  - Statistics & reporting
  - Custom CVE storage

- **[cve_matching_example.py](cve_matching_example.py)**
  - Version comparison algorithms
  - Semantic versioning
  - Fuzzy package name matching
  - Confidence scoring
  - Bulk matching

#### Complete Workflows
- **[docker_vulnerability_scan.py](docker_vulnerability_scan.py)**
  - End-to-end scanning
  - Generate JSON reports
  - Compare images
  - Filter by severity
  - Continuous monitoring

#### Utilities
- **[hash_usage.py](hash_usage.py)**
  - File hashing (SHA-256, MD5, SHA-1)
  - Integrity verification
  - Binary/text handling

## 🔧 Configuration Examples

### Environment Setup

```bash
# .env file
NVD_API_KEY=your_nvd_api_key_here
GITHUB_ACCESS_TOKEN=your_github_token_here
```

### API Rate Limits

| Mode | Requests | Interval |
|------|----------|----------|
| Without key | 5 | 30 seconds |
| With NVD key | 50 | 30 seconds |

Get free API key: https://nvd.nist.gov/developers/request-an-api-key

### Database Locations

```bash
# CVE Database
~/.threat_radar/cve.db

# Cache Directory
~/.threat_radar/cache/

# Cache organized by year
~/.threat_radar/cache/2021/CVE-2021-44228.json
~/.threat_radar/cache/2023/CVE-2023-12345.json
```

## 🎬 Video Tutorials (Simulated)

### Tutorial 1: Getting Started (10 min)
```bash
# Follow along:
python examples/docker_usage.py           # 2 min
python examples/nvd_basic_usage.py        # 3 min
threat-radar cve update --days 7          # 3 min
threat-radar cve scan-image alpine:3.18   # 2 min
```

### Tutorial 2: CVE Database (15 min)
```bash
# Follow along:
python examples/cve_database_usage.py     # 5 min
python examples/cve_matching_example.py   # 5 min
# See CLI_EXAMPLES.md workflows            # 5 min
```

### Tutorial 3: Production Scanning (20 min)
```bash
# Follow along:
python examples/docker_vulnerability_scan.py  # 10 min
# Build custom CI/CD workflow                  # 10 min
```

## 💡 Tips for Each Example

### docker_usage.py
- Run examples 1-4 first (fast)
- Example 5 requires network access
- Try with different images

### nvd_basic_usage.py
- Get API key first for better experience
- Examples 1-5 work without key (slower)
- Example 7 requires specific CVE to exist

### cve_database_usage.py
- Example 2 takes longest (initial update)
- Subsequent runs are much faster
- Try example 8 for complex queries

### docker_vulnerability_scan.py
- Example 1 is quickest
- Comment out slow examples first
- Uncomment for full workflow

### cve_matching_example.py
- All examples run offline (fast)
- Example 7 requires network
- Great for understanding algorithms

## 🐛 Troubleshooting

### Common Issues

**Import Errors:**
```bash
# Ensure installed
pip install -e .

# Or run from project root
PYTHONPATH=. python examples/nvd_basic_usage.py
```

**Docker Errors:**
```bash
# Check Docker is running
docker ps

# Pull image first
docker pull alpine:3.18
```

**Rate Limit Errors:**
```bash
# Get API key or wait
# Client automatically handles rate limiting
```

**Database Locked:**
```bash
# Stop other processes
# Or delete and reinitialize
rm ~/.threat_radar/cve.db
threat-radar cve update --days 30
```

## 🔗 Related Resources

### Internal
- Main README: [/README.md](../README.md)
- Development Guide: [/CLAUDE.md](../CLAUDE.md)
- Test Suite: [/tests/](../tests/)

### External
- NVD API Docs: https://nvd.nist.gov/developers
- CPE Search: https://nvd.nist.gov/products/cpe/search
- CycloneDX: https://cyclonedx.org/
- CVSS Calculator: https://www.first.org/cvss/calculator/3.1

## 📝 Example Code Patterns

### Context Managers (Recommended)

```python
from threat_radar.utils import docker_analyzer

# Automatic cleanup
with docker_analyzer() as analyzer:
    analysis = analyzer.analyze_container("alpine:3.18")
    # analyzer.close() called automatically
```

### Database Operations

```python
from threat_radar.core.cve_database import CVEDatabase

db = CVEDatabase()
try:
    db.update_from_nvd(days=30)
    cves = db.search_cves(severity="CRITICAL")
    # ... use cves
finally:
    db.close()
```

### Error Handling

```python
from threat_radar.core.nvd_client import NVDClient

client = NVDClient()
try:
    cve = client.get_cve_by_id("CVE-2021-44228")
    if cve:
        print(f"Found: {cve.cve_id}")
    else:
        print("CVE not found")
except Exception as e:
    print(f"Error: {e}")
finally:
    client.close()
```

## 🎓 Next Steps

1. **Choose your path:**
   - Security Engineer → Start with scanning workflows
   - Developer → Start with Docker analysis
   - DevOps → Start with CI/CD integration

2. **Run examples in order:**
   - Basic → Intermediate → Advanced

3. **Experiment:**
   - Modify examples for your images
   - Adjust confidence thresholds
   - Create custom workflows

4. **Contribute:**
   - Share your examples
   - Report issues
   - Improve documentation

## 📊 Examples Comparison

| Feature | docker_usage | nvd_basic | cve_database | cve_matching | full_scan |
|---------|--------------|-----------|--------------|--------------|-----------|
| Network Required | Yes | Yes | Yes (first run) | No | Yes |
| Docker Required | Yes | No | No | No | Yes |
| Speed | Fast | Slow | Fast | Fast | Slow |
| Complexity | Low | Low | Medium | Medium | High |
| Best For | Learning | API usage | DB operations | Algorithms | Production |

---

**Last Updated:** 2024-01-15
**Threat Radar Version:** 0.1.0
**Python Version:** 3.8+
