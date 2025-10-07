# Threat Radar (tr-nvd)

A comprehensive threat assessment and vulnerability analysis platform for Docker containers and software dependencies.

[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/)
[![Tests Passing](https://img.shields.io/badge/tests-15%2F15%20passing-brightgreen.svg)](docs/validation/EXAMPLES_TEST_RESULTS.md)
[![CVE Precision](https://img.shields.io/badge/CVE%20precision-100%25-brightgreen.svg)](docs/validation/DEBIAN8_VALIDATION_REPORT.md)

---

## 🎯 Overview

Threat Radar provides:
- 🐳 **Docker Container Analysis** - Extract and analyze packages from any Docker image
- 📦 **SBOM Generation** - Multi-format (CycloneDX, SPDX, Syft JSON) with Syft integration
- 🔍 **CVE Vulnerability Detection** - High-precision matching with NVD integration (0% false positives)
- 📊 **Comprehensive Reporting** - JSON, console output, validation analysis

---

## 🚀 Quick Start

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/tr-nvd.git
cd tr-nvd

# Install in development mode
pip install -e .

# Or with dev dependencies
pip install -e ".[dev]"
```

### Basic Usage

```bash
# Scan a Docker image for vulnerabilities
threat-radar docker scan ubuntu:14.04

# Generate SBOM for an image
threat-radar sbom generate alpine:3.18 -o sbom.json

# Search for CVEs
threat-radar cve search openssl --limit 10
```

### Python API

```python
from threat_radar.core.vulnerability_scanner import VulnerabilityScanner, ScanConfiguration
from threat_radar.utils import docker_analyzer

# Configure scanner
config = ScanConfiguration(
    min_confidence=0.75,
    max_cve_age_years=15,
    filter_disputed=True
)

# Analyze Docker image
with docker_analyzer() as analyzer:
    analysis = analyzer.import_container("ubuntu", "14.04")

# Scan for vulnerabilities
scanner = VulnerabilityScanner(config)
cves = scanner.fetch_cves(keywords=[('bash', 15)])
matches = scanner.scan(analysis, cves)
```

---

## 📚 Documentation

### Getting Started
- **[Project Overview](PROJECT_SUMMARY.md)** - Comprehensive feature documentation for stakeholders
- **[Examples Guide](examples/START_HERE.md)** - Step-by-step tutorials and examples
- **[CLI Reference](examples/CLI_EXAMPLES.md)** - Command-line usage guide
- **[Troubleshooting](examples/TROUBLESHOOTING.md)** - Common issues and solutions

### Technical Documentation
- **[SBOM Generation](docs/SBOM_SYFT.md)** - SBOM capabilities and formats
- **[Storage Organization](docs/SBOM_STORAGE_ORGANIZATION.md)** - SBOM file management
- **[Developer Guide](CLAUDE.md)** - Architecture and development workflows

### Validation & Reports
- **[Test Results](docs/validation/EXAMPLES_TEST_RESULTS.md)** - 15/15 examples passing (100%)
- **[Debian 8 Validation](docs/validation/DEBIAN8_VALIDATION_REPORT.md)** - 100% precision validation
- **[False Positive Analysis](docs/validation/FALSE_POSITIVE_ANALYSIS.md)** - Ubuntu 14.04 test results
- **[Improvement Reports](docs/reports/)** - CVE matching enhancements

### Development
- **[Code Review](docs/development/CODE_REVIEW_REPORT.md)** - Codebase quality analysis
- **[Refactoring Summary](docs/development/REFACTORING_SUMMARY.md)** - Recent code improvements
- **[Session Logs](docs/development/SESSION_SUMMARY.md)** - Development history

---

## ✨ Key Features

### 🐳 Docker Integration
- **Multi-distro support:** Alpine, Ubuntu, Debian, RHEL, CentOS, Fedora
- **Package extraction:** APK, APT/dpkg, YUM/rpm
- **Image comparison:** Diff packages between image versions
- **Python SBOM:** Extract pip packages and dependencies

### 📦 SBOM Generation
- **Syft integration:** Comprehensive package detection
- **Multiple formats:** CycloneDX, SPDX, Syft JSON
- **13 ecosystems:** Python, npm, Go, Rust, Java, Ruby, PHP, and more
- **License analysis:** Track package licenses across SBOM
- **Organized storage:** Automatic categorization (docker/, local/, comparisons/)

### 🔍 CVE Detection
- **NVD API integration:** Search and fetch CVEs by ID or keyword
- **High-precision matching:** 100% precision with 0 false positives
- **Fuzzy package matching:** Handles variations (openssl ↔ libssl, glibc ↔ libc6)
- **Version validation:** Semantic version range checking
- **Confidence scoring:** Transparent match quality assessment
- **Filtering:** Age-based, disputed CVE, vendor-specific

### 📊 Reporting
- **JSON reports:** Structured, machine-readable output
- **Console output:** Color-coded severity indicators
- **Validation analysis:** True positive/false positive breakdown
- **Statistics:** Severity distribution, confidence metrics

---

## 🧪 Validation Results

### Test Coverage
✅ **15/15 examples passing** (100% success rate)
✅ **33/33 matching tests passing**
✅ **Zero false positives** across all validation tests

### Precision Metrics
| Image | Packages | CVEs Found | False Positives | Precision |
|-------|----------|------------|-----------------|-----------|
| **Ubuntu 14.04** | 213 | 3 | 0 | 100% |
| **Debian 8** | 111 | 4 | 0 | 100% |

### Notable Detections
✅ Shellshock (CVE-2014-6271) - CRITICAL
✅ Bash variants (CVE-2014-7169) - CRITICAL
✅ glibc issues (CVE-2010-3192, CVE-2018-20796) - HIGH/MEDIUM

---

## 📁 Project Structure

```
tr-nvd/
├── threat_radar/              # Main package
│   ├── core/                  # Core functionality
│   │   ├── container_analyzer.py
│   │   ├── cve_matcher.py
│   │   ├── nvd_client.py
│   │   ├── syft_integration.py
│   │   └── vulnerability_scanner.py   [NEW]
│   ├── utils/                 # Utilities
│   │   ├── report_generator.py        [NEW]
│   │   ├── sbom_storage.py
│   │   └── docker_utils.py
│   └── cli/                   # CLI commands
│       ├── docker.py
│       ├── sbom.py
│       └── cve.py
├── examples/                  # Usage examples (15 scripts)
│   ├── 01_basic/             # Basic examples (4)
│   ├── 02_advanced/          # Advanced examples (4)
│   ├── 03_vulnerability_scanning/  # Scanning examples (5)
│   └── 04_testing/           # Test scripts (1)
├── docs/                      # Documentation
│   ├── validation/           # Test results and validation
│   ├── reports/              # Improvement reports
│   └── development/          # Development docs
├── tests/                     # Unit tests
└── sbom_storage/             # Generated SBOMs
    ├── docker/               # Docker image SBOMs
    ├── local/                # Local project SBOMs
    ├── comparisons/          # Image comparison results
    └── archives/             # Historical SBOMs
```

---

## 🛠️ Requirements

- **Python:** 3.9+
- **Docker:** Running Docker daemon
- **Syft:** Automatically installed via pip (anchore-syft>=1.18.0)

### Optional
- **NVD API Key:** For higher rate limits (configure in `.env`)

---

## 🔧 CLI Commands

### Docker Analysis
```bash
# Import and analyze image
threat-radar docker import-image alpine:3.18 -o analysis.json

# List packages in image
threat-radar docker packages ubuntu:22.04 --limit 20

# Generate Python SBOM
threat-radar docker python-sbom python:3.11 -o sbom.json
```

### SBOM Operations
```bash
# Generate SBOM with Syft
threat-radar sbom generate alpine:3.18 -f cyclonedx

# Compare two images
threat-radar sbom compare alpine:3.17 alpine:3.18
```

### CVE Operations
```bash
# Get CVE by ID
threat-radar cve get CVE-2014-6271

# Search CVEs
threat-radar cve search bash --limit 20
```

---

## 📊 Performance

### SBOM Generation
- **Alpine 3.18:** ~3 seconds (15 packages)
- **Python 3.11-slim:** ~5 seconds (97 packages)
- **Debian 8:** ~4 seconds (111 packages)
- **Ubuntu 14.04:** ~6 seconds (213 packages)

### CVE Matching
- **Ubuntu 14.04:** 46 CVEs scanned, 3 matches in <1 second
- **Debian 8:** 124 CVEs scanned, 4 matches in <1 second
- **Precision:** 100% (0 false positives)

---

## 🧑‍💻 Development

### Running Tests
```bash
# Run all unit tests
pytest

# Run specific test
pytest tests/test_docker_integration.py

# Run with coverage
pytest --cov=threat_radar --cov-report=html
```

### Code Quality
```bash
# Format code
black threat_radar/ tests/

# Type checking
mypy threat_radar/

# Linting
flake8 threat_radar/
```

### Examples
```bash
# Run all examples
cd examples
python 01_basic/hash_usage.py
python 03_vulnerability_scanning/demo_with_findings.py
```

---

## 📝 License

[Your License Here]

---

## 🤝 Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/yourusername/tr-nvd/issues)
- **Documentation:** [docs/](docs/)
- **Examples:** [examples/](examples/)

---

## 🏆 Acknowledgments

- **NVD:** NIST National Vulnerability Database
- **Syft:** Anchore's SBOM generation tool
- **Docker SDK:** Docker Python integration

---

**Status:** ✅ Production Ready | **Version:** 1.0.0 | **Last Updated:** 2025-10-06
