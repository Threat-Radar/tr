# Advanced Examples

These examples demonstrate advanced features and deeper integration capabilities.

## Examples

### 1. Advanced Docker Analysis
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

**Time:** ~5 minutes

---

### 2. Python SBOM Generation
**File:** `python_sbom_example.py`

Generate Software Bill of Materials (SBOM) for Python applications.

```bash
python python_sbom_example.py
```

**Features:**
- Extract Python packages from containers
- Generate CycloneDX SBOM format
- Multiple output formats (JSON, CSV, TXT)
- Dependency analysis

**Time:** ~2 minutes

---

### 3. CVE Matching Algorithms
**File:** `cve_matching_example.py`

Understand how package-to-CVE matching works.

```bash
python cve_matching_example.py
```

**Features:**
- Version comparison algorithms
- Semantic versioning
- Fuzzy package name matching
- Confidence scoring
- Bulk matching

**Time:** ~1 minute (runs offline)

---

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
- CI/CD integration examples

**Time:** ~3 minutes

---

## Example Workflows

### Compare Two Images

```python
from threat_radar.core.container_analyzer import ContainerAnalyzer
from threat_radar.utils import docker_analyzer

images = ["alpine:3.17", "alpine:3.18"]
results = {}

for image in images:
    with docker_analyzer() as analyzer:
        name, tag = image.split(':')
        analysis = analyzer.import_container(name, tag)
        results[image] = analysis

# Compare package counts, versions, etc.
```

### Generate SBOM for Production Image

```bash
# Using CLI
threat-radar docker python-sbom python:3.11 \
  -o production-sbom.json \
  --format cyclonedx

# Validate SBOM
cat production-sbom.json | jq '.components | length'
```

### Understand Match Confidence

```python
from threat_radar.core.cve_matcher import CVEMatcher, Package

package = Package(name="openssl", version="1.1.1", architecture="amd64")
matcher = CVEMatcher(min_confidence=0.7)

# This will explain why matches succeed or fail
matches = matcher.match_package(package, cves)
for match in matches:
    print(f"Confidence: {match.confidence:.0%}")
    print(f"Reason: {match.match_reason}")
```

## Prerequisites

- Completion of [01_basic](../01_basic/) examples recommended
- Understanding of Docker concepts
- Familiarity with SBOM standards (helpful but not required)

## Advanced Topics

### Custom Package Mappings

If you find legitimate packages not matching, add custom mappings:

```python
# In your code or fork
from threat_radar.core.cve_matcher import PackageNameMatcher

PackageNameMatcher.NAME_MAPPINGS["your-package"] = [
    "variant1", "variant2", "lib-yourpackage"
]
```

### Batch Processing

Process multiple images efficiently:

```python
from concurrent.futures import ThreadPoolExecutor

def scan_image(image):
    # Your scanning logic
    return results

images = ["ubuntu:20.04", "debian:11", "alpine:3.18"]

with ThreadPoolExecutor(max_workers=3) as executor:
    results = list(executor.map(scan_image, images))
```

## Next Steps

After mastering these examples:
- **[03_vulnerability_scanning](../03_vulnerability_scanning/)** - Complete vulnerability workflows
- **[04_testing](../04_testing/)** - Test and validate matching accuracy

## See Also

- [CLI_EXAMPLES.md](../CLI_EXAMPLES.md) - Complete CLI command reference
- [CVE Matching Documentation](../../MATCHING_IMPROVEMENTS.md) - Algorithm details
