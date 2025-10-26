# Changelog

All notable changes to Threat Radar will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-01-23

### Added
- **CVE Vulnerability Scanning** powered by Grype
  - Docker image scanning with automatic vulnerability detection
  - SBOM file scanning (CycloneDX, SPDX, Syft JSON)
  - Directory scanning for application dependencies
  - Severity filtering (NEGLIGIBLE, LOW, MEDIUM, HIGH, CRITICAL)
  - Auto-cleanup feature for Docker images
  - Auto-save feature with timestamped storage

- **AI-Powered Analysis**
  - Vulnerability analysis with exploitability assessment
  - Smart prioritization with urgency scoring
  - Remediation plan generation
  - Support for multiple AI providers:
    - OpenAI GPT-4o, GPT-4 Turbo
    - Anthropic Claude 3.5 Sonnet
    - Ollama (local models)
  - Batch processing for large CVE scans (100+ vulnerabilities)
  - Severity filtering to reduce analysis costs

- **Comprehensive Reporting**
  - Multiple output formats: JSON, Markdown, HTML
  - Report levels: Executive, Summary, Detailed, Critical-only
  - AI-powered executive summaries with risk ratings
  - Dashboard data export for Grafana/Prometheus
  - Trend analysis with scan comparison

- **SBOM Generation** powered by Syft
  - Multi-format support (CycloneDX, SPDX, Syft JSON)
  - Docker image analysis
  - Local directory scanning
  - 13+ package ecosystems (Python, npm, Go, Rust, Java, etc.)
  - Organized storage with categorization
  - SBOM comparison functionality

- **Docker Integration**
  - Multi-distro support (Alpine, Ubuntu, Debian, RHEL, CentOS, Fedora)
  - Package manager integration (APK, APT/dpkg, YUM/rpm)
  - Python package extraction
  - Image metadata inspection

- **CLI Features**
  - Modular command structure with Typer
  - Two CLI entry points: `threat-radar` and `tradar`
  - Comprehensive help system
  - Progress indicators for long-running operations
  - Configurable output formats

- **Storage Organization**
  - Automatic directory creation
  - Timestamped file naming
  - Organized by scan type (CVE, AI analysis, SBOM)
  - Historical tracking support

### Documentation
- Comprehensive README with quick start guide
- CLAUDE.md for AI-assisted development
- API reference documentation
- Installation and setup guides
- Troubleshooting guide
- 15+ example scripts
- CI/CD integration examples

### Testing
- 15/15 examples passing
- 100% CVE detection precision
- Comprehensive test suite with pytest
- Docker integration tests
- AI analysis tests
- Batch processing validation

### Infrastructure
- PyPI-ready package structure
- Type hints with mypy support
- Code formatting with Black
- Linting with flake8
- Continuous integration ready
- Git hooks compatible

## [Unreleased]

### Planned Features
- Enhanced ontology support for threat modeling
- Advanced risk assessment algorithms
- Threat scenario simulations
- GitHub Security Advisory integration
- Web dashboard UI
- REST API server
- Database backend for scan history
- Custom report templates
- Multi-language support
- Plugin system for extensibility

---

[0.1.0]: https://github.com/yourusername/threat-radar/releases/tag/v0.1.0
