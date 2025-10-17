# Threat Radar Examples

Comprehensive examples demonstrating the Threat Radar vulnerability management platform with Grype-powered CVE scanning, AI analysis, and comprehensive reporting.

## 📁 Directory Structure

```
examples/
├── 01_basic/                    # Start here! Fundamental operations
│   ├── docker_usage.py          # Docker container analysis
│   ├── nvd_basic_usage.py       # Fetch CVEs from NVD (historical)
│   ├── cve_database_usage.py    # Local CVE database (historical)
│   └── hash_usage.py            # File integrity hashing
│
├── 02_advanced/                 # Advanced features
│   ├── docker_advanced.py       # Batch analysis, comparisons
│   ├── python_sbom_example.py   # SBOM generation
│   ├── syft_sbom_example.py     # Syft SBOM integration
│   └── docker_cli_examples.sh   # CLI workflows
│
├── 03_vulnerability_scanning/   # Legacy NVD-based scanning
│   ├── demo_with_findings.py    # Historical NVD scanning
│   ├── scan_vulnerable_image.py # Historical workflows
│   └── docker_vulnerability_scan.py  # Legacy examples
│
├── 04_testing/                  # Testing & validation
│   ├── test_matching_accuracy.py     # Matching tests
│   └── debug_matching.py             # Debug tool
│
├── 05_reporting/                # ⭐ NEW: Comprehensive Reporting
│   ├── 01_basic_report_generation.py      # Multi-format reports
│   ├── 02_ai_powered_reports.py           # AI executive summaries
│   ├── 03_dashboard_integration.py        # Dashboard data
│   └── README.md                          # Reporting guide
│
└── Documentation
    ├── README.md               # This file
    ├── CLI_EXAMPLES.md         # CLI command reference
    └── TROUBLESHOOTING.md      # Common issues & solutions
```

## 🚀 Quick Start

### For New Users (5 minutes)

```bash
# 1. Basic Docker analysis
python 01_basic/docker_usage.py

# 2. Generate SBOM with Syft
python 02_advanced/syft_sbom_example.py

# 3. Scan for vulnerabilities with Grype ⭐ RECOMMENDED
threat-radar cve scan-image alpine:3.18

# 4. Generate comprehensive report
threat-radar report generate scan-results.json -o report.html -f html
```

### Modern Workflow (Recommended)

```bash
# 1. Scan Docker image for vulnerabilities (Grype-powered)
threat-radar cve scan-image alpine:3.18 --auto-save -o scan.json

# 2. Generate comprehensive HTML report
threat-radar report generate scan.json -o report.html -f html --level detailed

# 3. AI-powered analysis (optional)
threat-radar ai analyze scan.json --auto-save
threat-radar ai prioritize scan.json --top 10

# 4. Export dashboard data
threat-radar report dashboard-export scan.json -o dashboard.json
```

## 📚 Learning Path

### Beginner Track (New Architecture)

**Day 1: Modern Tooling**
1. `01_basic/docker_usage.py` - Docker container analysis
2. `02_advanced/syft_sbom_example.py` - SBOM generation with Syft
3. **CLI:** `threat-radar cve scan-image alpine:3.18` - Grype vulnerability scanning

**Day 2: Reporting & Analysis**
4. **CLI:** `threat-radar report generate` - Comprehensive reporting
5. `05_reporting/01_basic_report_generation.py` - Report formats
6. `05_reporting/02_ai_powered_reports.py` - AI-powered insights

**Day 3: Production Workflows**
7. `05_reporting/03_dashboard_integration.py` - Dashboard integration
8. **CLI:** `threat-radar ai analyze` - AI vulnerability analysis
9. Review `CLI_EXAMPLES.md` - Production workflows

### Legacy Examples (Historical Reference)

These examples use the older NVD-based scanning approach:
- `03_vulnerability_scanning/` - Legacy NVD scanning workflows
- `01_basic/nvd_basic_usage.py` - Historical NVD API usage
- `01_basic/cve_database_usage.py` - Historical local database

**Note:** For new projects, use Grype-based scanning via the CLI instead.

## 🎯 Examples by Feature

### CVE Vulnerability Scanning (Modern - Grype)

```bash
# Scan Docker image
threat-radar cve scan-image alpine:3.18

# Scan with severity filter
threat-radar cve scan-image python:3.11 --severity HIGH

# Scan SBOM file
threat-radar cve scan-sbom my-app-sbom.json

# Scan local directory
threat-radar cve scan-directory ./my-project

# Auto-save with cleanup
threat-radar cve scan-image nginx:latest --auto-save --cleanup
```

**Learn more:** [../CLAUDE.md#cve-commands-reference](../CLAUDE.md)

### SBOM Generation

**Python API:**
→ `02_advanced/python_sbom_example.py` - Python-specific SBOM
→ `02_advanced/syft_sbom_example.py` - Comprehensive Syft integration

**CLI:**
```bash
# Generate SBOM from Docker image
threat-radar sbom docker alpine:3.18 -o sbom.json

# Generate from local directory
threat-radar sbom generate ./my-app -f cyclonedx-json

# Compare two SBOMs
threat-radar sbom compare alpine:3.17 alpine:3.18
```

### Comprehensive Reporting

**Python API:**
→ `05_reporting/01_basic_report_generation.py` - JSON, Markdown, HTML
→ `05_reporting/02_ai_powered_reports.py` - AI executive summaries
→ `05_reporting/03_dashboard_integration.py` - Grafana/Prometheus data

**CLI:**
```bash
# Generate HTML report with AI summary
threat-radar report generate scan.json -o report.html -f html

# Executive summary for leadership
threat-radar report generate scan.json -o exec.md --level executive

# Critical-only issues
threat-radar report generate scan.json --level critical-only

# Export dashboard data
threat-radar report dashboard-export scan.json -o dashboard.json
```

**Full guide:** [05_reporting/README.md](05_reporting/README.md)

### AI-Powered Analysis

```bash
# Analyze vulnerabilities
threat-radar ai analyze scan-results.json --auto-save

# Generate prioritized remediation list
threat-radar ai prioritize scan-results.json --top 10

# Create remediation plan
threat-radar ai remediate scan-results.json -o plan.json
```

**Learn more:** [../CLAUDE.md#ai-commands-reference](../CLAUDE.md)

### Docker Analysis

**Python API:**
→ `01_basic/docker_usage.py` - Basic container analysis
→ `02_advanced/docker_advanced.py` - Advanced features

**CLI:**
```bash
# Import and analyze image
threat-radar docker import-image ubuntu:22.04 -o analysis.json

# List packages
threat-radar docker packages alpine:3.18 --limit 20

# Generate Python SBOM
threat-radar docker python-sbom python:3.11 -o sbom.json
```

## ⚙️ Prerequisites

### Required
- Python 3.8+
- Docker daemon running
- **[Grype](https://github.com/anchore/grype)** - For CVE scanning
- **[Syft](https://github.com/anchore/syft)** - For SBOM generation

### Installation

```bash
# Install external tools
brew install grype syft  # macOS
# or see installation guide in main README

# Install Threat Radar
pip install -e ..

# Verify installation
threat-radar --help
grype version
syft version
```

### Optional
- **OpenAI API key** - For AI-powered analysis
- **Ollama** - For local AI models (privacy-focused)

## 📖 Documentation

### Getting Started
- **[Main README](../README.md)** - Project overview and installation
- **[CLAUDE.md](../CLAUDE.md)** - Complete CLI reference
- **[Reporting Guide](../docs/REPORTING_GUIDE.md)** - Report generation guide

### Feature Guides
- **[05_reporting/README.md](05_reporting/README.md)** - Comprehensive reporting
- **[05_reporting/EXAMPLES_SUMMARY.md](05_reporting/EXAMPLES_SUMMARY.md)** - Reporting examples
- **[CLI_EXAMPLES.md](CLI_EXAMPLES.md)** - Command-line workflows
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Common issues

### Technical
- **[SBOM Documentation](../docs/SBOM_SYFT.md)** - SBOM capabilities
- **[Developer Guide](../CLAUDE.md)** - Architecture and development

## 🔄 Migration from NVD to Grype

If you're using the legacy NVD-based examples in `03_vulnerability_scanning/`:

### Old Workflow (Legacy)
```python
# Legacy NVD-based scanning
from threat_radar.core.nvd_client import NVDClient
from threat_radar.core.vulnerability_scanner import VulnerabilityScanner

client = NVDClient()
scanner = VulnerabilityScanner()
# ... manual CVE fetching and matching
```

### New Workflow (Modern)
```bash
# Modern Grype-based scanning
threat-radar cve scan-image alpine:3.18 --auto-save -o scan.json
threat-radar report generate scan.json -o report.html -f html
threat-radar ai analyze scan.json --auto-save
```

**Benefits:**
- ✅ Faster (local vulnerability database)
- ✅ More accurate (Grype's proven engine)
- ✅ Zero API rate limits
- ✅ Comprehensive package coverage
- ✅ AI-powered insights
- ✅ Professional reporting

## 🎯 Recommended Workflows

### Weekly Security Scan

```bash
#!/bin/bash
# weekly-scan.sh

IMAGE="myapp:production"
WEEK=$(date +%Y-W%U)

# Scan for vulnerabilities
threat-radar cve scan-image $IMAGE --auto-save -o scan-${WEEK}.json

# Generate reports
threat-radar report generate scan-${WEEK}.json -o exec-${WEEK}.md --level executive
threat-radar report generate scan-${WEEK}.json -o detailed-${WEEK}.html -f html

# AI analysis
threat-radar ai analyze scan-${WEEK}.json --auto-save
threat-radar ai prioritize scan-${WEEK}.json --top 10 -o priorities-${WEEK}.json

# Export dashboard data
threat-radar report dashboard-export scan-${WEEK}.json -o dashboard-${WEEK}.json
```

### CI/CD Integration

```yaml
# .github/workflows/security-scan.yml
- name: Scan for vulnerabilities
  run: |
    threat-radar cve scan-image app:${{ github.sha }} \
      --auto-save --cleanup -o scan.json

    threat-radar report generate scan.json --level critical-only -o critical.json

    CRITICAL=$(jq '.summary.critical' critical.json)
    if [ $CRITICAL -gt 0 ]; then
      echo "❌ Found $CRITICAL critical vulnerabilities!"
      exit 1
    fi
```

## 📊 Quick Command Reference

```bash
# CVE Scanning
threat-radar cve scan-image <image>              # Scan Docker image
threat-radar cve scan-sbom <file>                # Scan SBOM
threat-radar cve scan-directory <path>           # Scan directory

# SBOM Generation
threat-radar sbom docker <image> -o sbom.json    # Generate SBOM
threat-radar sbom compare <sbom1> <sbom2>        # Compare SBOMs

# Reporting
threat-radar report generate <scan> -o report.html  # Generate report
threat-radar report dashboard-export <scan>         # Export dashboard data

# AI Analysis
threat-radar ai analyze <scan>                   # Analyze vulnerabilities
threat-radar ai prioritize <scan> --top 10       # Prioritize remediation
threat-radar ai remediate <scan>                 # Generate remediation plan

# Docker Analysis
threat-radar docker import-image <image>         # Analyze image
threat-radar docker packages <image>             # List packages
```

## 🐛 Troubleshooting

### Common Issues

**Grype not installed**
```bash
brew install grype  # macOS
# or see https://github.com/anchore/grype
```

**Syft not installed**
```bash
brew install syft  # macOS
# or see https://github.com/anchore/syft
```

**OpenAI API errors (for AI features)**
- Check your API key in `.env`
- Or use Ollama for local AI: `brew install ollama`

**Full troubleshooting guide:** [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

## 💡 Tips

1. **Start with Grype** - Use `threat-radar cve scan-image` instead of legacy NVD examples
2. **Use Auto-save** - Add `--auto-save` to organize scan results automatically
3. **Generate Reports** - Use the reporting system for professional output
4. **Try AI Features** - Get intelligent insights with `threat-radar ai analyze`
5. **Export Dashboard Data** - Integrate with Grafana, Prometheus, or custom dashboards

## 🔗 Next Steps

After exploring examples:

1. ✅ Run `threat-radar cve scan-image alpine:3.18`
2. ✅ Generate your first report
3. ✅ Try AI-powered analysis
4. → Build custom workflows
5. → Integrate into CI/CD
6. → Deploy to production

**Full documentation:** [../README.md](../README.md)

---

**Quick start:** `threat-radar cve scan-image alpine:3.18 && threat-radar report generate scan.json -o report.html -f html`
