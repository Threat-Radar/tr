# Troubleshooting Guide

Common issues and solutions when running Threat Radar examples.

## Docker Image Not Found

### Problem
```
docker.errors.ImageNotFound: 404 Client Error for http+docker://localhost/v1.51/images/ubuntu:20.04/json:
Not Found ("No such image: ubuntu:20.04")
```

### Solution
The examples now automatically pull images, but if you encounter this error:

**Option 1: Pull manually first**
```bash
docker pull ubuntu:20.04
docker pull alpine:3.18
docker pull nginx:alpine
```

**Option 2: Use import_container instead of analyze_container**
```python
# Instead of:
analysis = analyzer.analyze_container("ubuntu:20.04")

# Use:
analysis = analyzer.import_container("ubuntu", "20.04")
```

**Option 3: Use images you already have**
```bash
# Check what images you have
docker images

# Use one of those in the example
python examples/docker_usage.py
```

---

## Docker Daemon Not Running

### Problem
```
docker.errors.DockerException: Error while fetching server API version
ConnectionError: ('Connection aborted.', FileNotFoundError(2, 'No such file or directory'))
```

### Solution

**macOS:**
```bash
# Start Docker Desktop
open /Applications/Docker.app

# Or via CLI
open -a Docker

# Verify it's running
docker ps
```

**Linux:**
```bash
# Start Docker service
sudo systemctl start docker

# Enable on boot
sudo systemctl enable docker

# Verify
docker ps
```

**Windows (WSL2):**
```bash
# Start Docker Desktop
# Or restart WSL
wsl --shutdown
```

---

## NVD API Rate Limit Exceeded

### Problem
```
requests.exceptions.HTTPError: 403 Client Error: Forbidden
```

### Solution

**Option 1: Get an API Key (Recommended)**
```bash
# Get free key from: https://nvd.nist.gov/developers/request-an-api-key
echo "NVD_API_KEY=your_key_here" >> .env

# This increases limit from 5 to 50 requests per 30 seconds
```

**Option 2: Use Local Database**
```bash
# Update database once
threat-radar cve update --days 30

# Then search locally (no API calls)
threat-radar cve db-search --severity CRITICAL
```

**Option 3: Add delays**
```python
import time

for cve_id in cve_list:
    cve = client.get_cve_by_id(cve_id)
    time.sleep(6)  # Wait 6 seconds between requests
```

---

## Module Import Errors

### Problem
```
ModuleNotFoundError: No module named 'threat_radar'
```

### Solution

**Option 1: Install in editable mode**
```bash
cd /path/to/tr-nvd
pip install -e .
```

**Option 2: Set PYTHONPATH**
```bash
export PYTHONPATH=/path/to/tr-nvd:$PYTHONPATH
python examples/nvd_basic_usage.py
```

**Option 3: Run from project root**
```bash
cd /path/to/tr-nvd
PYTHONPATH=. python examples/nvd_basic_usage.py
```

---

## Database Locked Error

### Problem
```
sqlite3.OperationalError: database is locked
```

### Solution

**Option 1: Close other processes**
```bash
# Find processes using the database
lsof ~/.threat_radar/cve.db

# Kill them
pkill -f threat-radar
```

**Option 2: Delete and recreate**
```bash
rm ~/.threat_radar/cve.db
threat-radar cve update --days 30
```

**Option 3: Use separate database per process**
```python
import tempfile
db = CVEDatabase(db_path=tempfile.mktemp(suffix='.db'))
```

---

## Package Name Not Matching

### Problem
CVEs not being detected for packages that should match.

### Solution

**Lower confidence threshold:**
```bash
# Default is 0.7
threat-radar cve scan-image alpine:3.18 --confidence 0.5
```

**Check package name variations:**
```python
from threat_radar.core.cve_matcher import PackageNameMatcher

score = PackageNameMatcher.similarity_score("libssl", "openssl")
print(f"Similarity: {score}")  # Should be high

# Check if likely match
is_match = PackageNameMatcher.is_likely_match("libssl", "openssl")
print(f"Match: {is_match}")  # Should be True
```

**Add custom mappings:**
```python
# In cve_matcher.py, add to NAME_MAPPINGS
PackageNameMatcher.NAME_MAPPINGS["your-package"] = [
    "alternative-name-1",
    "alternative-name-2"
]
```

---

## Cache Issues

### Problem
Stale or corrupted cache data.

### Solution

**Clear all cache:**
```bash
threat-radar cve clear-cache --yes
```

**Clear old cache only:**
```bash
threat-radar cve clear-cache --older-than 7 --yes
```

**Manual deletion:**
```bash
rm -rf ~/.threat_radar/cache/
```

**Disable cache for specific request:**
```bash
threat-radar cve get CVE-2021-44228 --no-cache
```

---

## Permission Errors

### Problem
```
PermissionError: [Errno 13] Permission denied: '/Users/user/.threat_radar'
```

### Solution

**Fix permissions:**
```bash
sudo chown -R $USER:$USER ~/.threat_radar
chmod -R 755 ~/.threat_radar
```

**Use custom directory:**
```python
import tempfile
client = NVDClient(cache_dir=tempfile.mkdtemp())
db = CVEDatabase(db_path="/tmp/cve.db")
```

---

## Network/Proxy Issues

### Problem
```
requests.exceptions.ConnectionError: Failed to establish connection
```

### Solution

**Check internet connection:**
```bash
curl -I https://services.nvd.nist.gov/rest/json/cves/2.0
```

**Set proxy (if needed):**
```bash
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
```

**Or in Python:**
```python
import os
os.environ['HTTP_PROXY'] = 'http://proxy.company.com:8080'
os.environ['HTTPS_PROXY'] = 'http://proxy.company.com:8080'
```

---

## Test Failures

### Problem
Tests fail with Docker-related errors.

### Solution

**Skip Docker tests:**
```bash
pytest tests/ -k "not docker"
```

**Run only NVD tests:**
```bash
pytest tests/test_nvd_integration.py -v
```

**Skip network tests:**
```bash
pytest tests/ -m "not network"
```

---

## Performance Issues

### Problem
Examples run very slowly.

### Solution

**Use API key:**
- Get from https://nvd.nist.gov/developers/request-an-api-key
- Set in `.env`: `NVD_API_KEY=your_key`
- Increases from 5 to 50 req/30s

**Use local database:**
```bash
# Build once
threat-radar cve update --days 90

# Then search locally (instant)
threat-radar cve db-search --severity HIGH
```

**Reduce search scope:**
```bash
# Instead of 5000 CVEs
threat-radar cve db-search --limit 100
```

**Parallel processing:**
```python
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=5) as executor:
    futures = [executor.submit(scan_image, img) for img in images]
    results = [f.result() for f in futures]
```

---

## Version Comparison Not Working

### Problem
Version ranges not matching correctly.

### Solution

**Test version comparison:**
```python
from threat_radar.core.cve_matcher import VersionComparator

# Test comparison
result = VersionComparator.compare_versions("1.2.3", "1.2.4")
print(result)  # -1 (less than)

# Test range
in_range = VersionComparator.is_version_in_range(
    "2.5.0",
    start_including="2.0.0",
    end_including="3.0.0"
)
print(in_range)  # True
```

**Check version parsing:**
```python
parts, suffix = VersionComparator.parse_version("v2.0.0-beta")
print(f"Parts: {parts}, Suffix: {suffix}")
# Parts: [2, 0, 0], Suffix: beta
```

---

## Memory Issues

### Problem
```
MemoryError: Unable to allocate array
```

### Solution

**Process in batches:**
```python
batch_size = 100
for i in range(0, len(packages), batch_size):
    batch = packages[i:i+batch_size]
    matches = matcher.bulk_match_packages(batch, cves)
```

**Limit CVE results:**
```python
# Instead of all CVEs
cves = db.search_cves(limit=1000)  # Limit to 1000
```

**Clear variables:**
```python
import gc

# After processing
del large_data
gc.collect()
```

---

## Common Environment Issues

### macOS Apple Silicon (M1/M2)
```bash
# Use native arm64 Python
python --version  # Should show arm64

# If using Rosetta, reinstall Python natively
brew install python@3.11
```

### Windows WSL
```bash
# Ensure Docker integration is enabled
# Docker Desktop -> Settings -> Resources -> WSL Integration
# Enable integration with your WSL distro
```

### Virtual Environment
```bash
# Ensure venv is activated
source .venv/bin/activate  # Linux/macOS
.venv\Scripts\activate     # Windows

# Verify
which python  # Should point to .venv
```

---

## Getting Help

If none of these solutions work:

1. **Check logs:**
   ```bash
   # Enable debug logging
   export THREAT_RADAR_DEBUG=1
   python examples/nvd_basic_usage.py
   ```

2. **Minimal reproducer:**
   ```python
   # Create minimal test
   from threat_radar.core.nvd_client import NVDClient

   client = NVDClient()
   cve = client.get_cve_by_id("CVE-2021-44228")
   print(cve)
   ```

3. **Check versions:**
   ```bash
   python --version
   docker --version
   pip show threat-radar
   ```

4. **File an issue:**
   - Include error message
   - Include Python/Docker versions
   - Include minimal reproducer
   - GitHub: https://github.com/anthropics/claude-code/issues

---

## Quick Diagnostics

Run this diagnostic script:

```bash
#!/bin/bash
echo "=== Threat Radar Diagnostics ==="
echo
echo "Python Version:"
python --version
echo
echo "Docker Status:"
docker ps 2>&1 | head -1
echo
echo "Threat Radar Installation:"
pip show threat-radar | grep -E "^(Name|Version|Location)"
echo
echo "Database Status:"
ls -lh ~/.threat_radar/cve.db 2>/dev/null || echo "No database found"
echo
echo "Cache Status:"
du -sh ~/.threat_radar/cache/ 2>/dev/null || echo "No cache found"
echo
echo "Environment:"
env | grep -E "(NVD_API_KEY|DOCKER|HTTP)" || echo "No relevant env vars"
```

Save as `diagnose.sh`, run with `bash diagnose.sh`
