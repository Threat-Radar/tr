# Documentation Index

Complete guide to Threat Radar documentation.

---

## 📖 Quick Links

- **[Main README](../README.md)** - Project overview and quick start
- **[Developer Guide](../CLAUDE.md)** - Comprehensive development guide
- **[Examples Guide](../examples/README.md)** - Step-by-step tutorials

---

## 📂 Documentation Structure

```
docs/
├── INDEX.md                           # This file
├── API.md                             # Python API reference
├── CLI_FEATURES.md                    # CLI features guide
├── REPORTING_GUIDE.md                 # Report generation guide
├── SBOM_SYFT.md                       # SBOM generation guide
├── reports/                           # (Empty - historical reports removed)
└── development/                       # Developer documentation
    ├── CODE_REVIEW_REPORT.md          # Code quality review
    ├── REFACTORING_SUMMARY.md         # Recent refactoring
    └── SESSION_SUMMARY.md             # Development history
```

---

## 🎯 By Topic

### Getting Started

| Document | Description | Audience |
|----------|-------------|----------|
| [README](../README.md) | Project overview, installation, quick start | Everyone |
| [INSTALLATION](../INSTALLATION.md) | Detailed installation instructions | New Users |
| [Examples Guide](../examples/README.md) | Step-by-step tutorials | New Users |
| [CLI Examples](../examples/CLI_EXAMPLES.md) | Command reference | CLI Users |

### Features & Capabilities

| Document | Description | Topic |
|----------|-------------|-------|
| [CLI Features](CLI_FEATURES.md) | CLI options and configuration | CLI |
| [SBOM Generation](SBOM_SYFT.md) | SBOM generation capabilities | SBOM |
| [Reporting](REPORTING_GUIDE.md) | Report generation and formats | Reporting |
| [API Reference](API.md) | Python API documentation | Development |
| [Developer Guide](../CLAUDE.md) | Architecture & workflows | Development |

### Development

| Document | Description | For |
|----------|-------------|-----|
| [Code Review](development/CODE_REVIEW_REPORT.md) | Quality analysis | Developers |
| [Refactoring Summary](development/REFACTORING_SUMMARY.md) | Recent changes | Developers |
| [Session Logs](development/SESSION_SUMMARY.md) | Development history | Maintainers |
| [Developer Guide](../CLAUDE.md) | Architecture guide | Contributors |

---

## 🔍 By Use Case

### I want to...

#### Learn about the project
1. Start with [README](../README.md)
2. Read [INSTALLATION](../INSTALLATION.md)
3. Try [Examples Guide](../examples/README.md)

#### Use Threat Radar
1. Read [README - Quick Start](../README.md#quick-start)
2. Follow [Examples Guide](../examples/README.md)
3. Reference [CLI Examples](../examples/CLI_EXAMPLES.md)
4. Check [Troubleshooting](../examples/TROUBLESHOOTING.md) if needed

#### Generate SBOMs
1. Read [SBOM_SYFT](SBOM_SYFT.md)
2. Try [SBOM Examples](../examples/02_advanced/)
3. Use CLI: `threat-radar sbom --help`

#### Scan for vulnerabilities
1. Read [Developer Guide - CVE Scanning](../CLAUDE.md#cve-commands-reference-powered-by-grype)
2. Run [Vulnerability Examples](../examples/03_vulnerability_scanning/)
3. Use CLI: `threat-radar cve scan-image alpine:3.18`

#### Generate reports
1. Read [Reporting Guide](REPORTING_GUIDE.md)
2. Try [Reporting Examples](../examples/05_reporting/)
3. Use CLI: `threat-radar report --help`

#### Contribute to development
1. Read [Developer Guide](../CLAUDE.md)
2. Review [Code Review Report](development/CODE_REVIEW_REPORT.md)
3. Check [Refactoring Summary](development/REFACTORING_SUMMARY.md)
4. See [Session Logs](development/SESSION_SUMMARY.md)

---

## 📊 Documentation Statistics

| Category | Files | Status |
|----------|-------|--------|
| **Root Documentation** | 5 | ✅ Complete |
| **Feature Guides** | 4 | ✅ Complete |
| **Development Docs** | 3 | ✅ Complete |
| **Examples** | 3 | ✅ Complete |
| **TOTAL** | **15** | **✅ Complete** |

---

## 🆕 Recent Updates

### 2025-11-15
- ✅ Consolidated documentation structure
- ✅ Removed duplicative and historical documents
- ✅ Updated all cross-references
- ✅ Streamlined to essential documentation only

---

## 🔗 External Resources

- [Grype Documentation](https://github.com/anchore/grype)
- [Syft Documentation](https://github.com/anchore/syft)
- [CycloneDX Specification](https://cyclonedx.org/)
- [SPDX Specification](https://spdx.dev/)

---

**Last Updated:** 2025-11-15
**Documentation Version:** 2.0
**Maintained By:** Threat Radar Team
