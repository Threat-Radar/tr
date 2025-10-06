# Threat Radar Examples

Comprehensive examples demonstrating the Threat Radar vulnerability management platform.

## 📁 Directory Structure

```
examples/
├── 01_basic/                    # Start here! Fundamental operations
│   ├── docker_usage.py          # Docker container analysis
│   ├── nvd_basic_usage.py       # Fetch CVEs from NVD
│   ├── cve_database_usage.py    # Local CVE database
│   └── hash_usage.py            # File integrity hashing
│
├── 02_advanced/                 # Advanced features
│   ├── docker_advanced.py       # Batch analysis, comparisons
│   ├── python_sbom_example.py   # SBOM generation
│   ├── cve_matching_example.py  # Matching algorithms
│   └── docker_cli_examples.sh   # CLI workflows
│
├── 03_vulnerability_scanning/   # Complete scanning workflows
│   ├── demo_with_findings.py    # ⭐ Recommended: Real CVE detection
│   ├── scan_vulnerable_image.py # Scan Ubuntu 18.04
│   ├── docker_vulnerability_scan.py  # 6 comprehensive examples
│   └── quick_vulnerability_demo.py   # Quick demo (no API key)
│
├── 04_testing/                  # Testing & validation
│   ├── test_matching_accuracy.py     # Comprehensive test suite
│   └── debug_matching.py             # Debug tool
│
├── output/                      # Generated reports (gitignored)
│
└── Documentation
    ├── README.md               # This file
    ├── CLI_EXAMPLES.md         # CLI command reference
    ├── INDEX.md                # Detailed navigation guide
    └── TROUBLESHOOTING.md      # Common issues & solutions
```

## 🚀 Quick Start

### First-Time Users (5 minutes)

```bash
# 1. Basic Docker analysis
python 01_basic/docker_usage.py

# 2. Fetch famous CVE (Shellshock)
python 01_basic/nvd_basic_usage.py

# 3. See real vulnerabilities! ⭐
python 03_vulnerability_scanning/demo_with_findings.py
```

### With NVD API Key (Recommended)

```bash
# 1. Get free API key from https://nvd.nist.gov/developers/request-an-api-key
echo "NVD_API_KEY=your_key_here" >> ../.env

# 2. Build comprehensive database
threat-radar cve update --days 90

# 3. Scan for vulnerabilities
python 03_vulnerability_scanning/scan_vulnerable_image.py
```

## 📚 Learning Path

### Beginner Track

**Day 1: Docker & CVE Basics**
1. `01_basic/docker_usage.py` - Learn Docker analysis
2. `01_basic/nvd_basic_usage.py` - Understand CVEs
3. `01_basic/cve_database_usage.py` - Local database

**Day 2: First Vulnerability Scan**
4. `03_vulnerability_scanning/quick_vulnerability_demo.py` - Quick scan
5. `03_vulnerability_scanning/demo_with_findings.py` - Real findings

**Day 3: Understanding Results**
6. `02_advanced/cve_matching_example.py` - How matching works
7. `04_testing/test_matching_accuracy.py` - Validate accuracy

### Intermediate Track

**Week 1: Advanced Analysis**
1. `02_advanced/docker_advanced.py` - Batch processing
2. `02_advanced/python_sbom_example.py` - SBOM generation
3. `03_vulnerability_scanning/docker_vulnerability_scan.py` - All 6 examples

**Week 2: Production Integration**
4. Study `CLI_EXAMPLES.md` - CLI workflows
5. Build custom scanning scripts
6. Integrate with CI/CD (see examples in `CLI_EXAMPLES.md`)

### Advanced Track

**Production Deployment**
1. Set up continuous monitoring
2. Configure CI/CD pipelines
3. Build custom scanning tools
4. Create automated reports

## 🎯 Examples by Use Case

### I want to...

#### Scan a Docker image for vulnerabilities
→ `03_vulnerability_scanning/demo_with_findings.py` ⭐

#### Generate an SBOM for compliance
→ `02_advanced/python_sbom_example.py`

#### Compare two image versions
→ `02_advanced/docker_advanced.py` (Example 4)

#### Understand matching accuracy
→ `04_testing/test_matching_accuracy.py`

#### Integrate into CI/CD
→ `CLI_EXAMPLES.md` (Workflow 4)

#### Work offline with CVEs
→ `01_basic/cve_database_usage.py`

#### Debug a false positive
→ `04_testing/debug_matching.py`

## ⚙️ Prerequisites

### Required
- Python 3.8+
- Docker daemon running
- Internet connection (for NVD API)

### Optional but Recommended
- NVD API key ([get free key](https://nvd.nist.gov/developers/request-an-api-key))
- Increases rate limit from 5 to 50 requests/30s

### Installation

```bash
# Install Threat Radar
pip install -e ..

# Verify installation
threat-radar --help
```

## 📊 Example Comparison

| Example | Network | Docker | Speed | Complexity | Best For |
|---------|---------|--------|-------|------------|----------|
| `docker_usage.py` | ✓ | ✓ | Fast | Low | Learning basics |
| `nvd_basic_usage.py` | ✓ | ✗ | Slow | Low | Understanding CVEs |
| `cve_database_usage.py` | ✓* | ✗ | Fast | Medium | Offline work |
| `demo_with_findings.py` | ✓ | ✓ | Medium | Medium | **Recommended first scan** |
| `docker_vulnerability_scan.py` | ✓ | ✓ | Slow | High | Production workflows |

\* Only for initial database population

## 🔧 Configuration

### Environment Variables

Create `.env` file in project root:

```bash
# NVD API Key (optional, increases rate limits)
NVD_API_KEY=your_nvd_api_key_here

# GitHub Access Token (for GitHub integration)
GITHUB_ACCESS_TOKEN=your_github_token_here
```

### Rate Limits

| Mode | Requests | Interval |
|------|----------|----------|
| No API key | 5 | 30 seconds |
| With NVD key | 50 | 30 seconds |

Get API key: https://nvd.nist.gov/developers/request-an-api-key

## 📝 Output Files

Examples generate various output files:

```
output/
├── vulnerability_report_*.json     # Detailed scan results
├── vulnerability_summary_*.txt     # Human-readable summaries
├── alpine_analysis.json            # Container analysis
└── sbom.json                       # SBOM outputs
```

All output files are gitignored automatically.

## 🐛 Troubleshooting

**Common Issues:**

1. **Docker image not found**
   - Examples now auto-pull images
   - Or manually: `docker pull alpine:3.18`

2. **NVD rate limit exceeded**
   - Get API key for higher limits
   - Or use local database: `threat-radar cve update`

3. **No vulnerabilities detected**
   - Try older images: `ubuntu:14.04`
   - Lower confidence: `--confidence 0.6`
   - Build larger database: `threat-radar cve update --days 365`

**Full troubleshooting guide:** [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

## 📖 Documentation

- **[CLI_EXAMPLES.md](CLI_EXAMPLES.md)** - Complete CLI reference with workflows
- **[INDEX.md](INDEX.md)** - Detailed navigation guide
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Solutions for common issues
- **[MATCHING_IMPROVEMENTS.md](../MATCHING_IMPROVEMENTS.md)** - Algorithm improvements
- **[Main README](../README.md)** - Project overview

## 🧪 Testing

Validate the system works correctly:

```bash
# Run accuracy tests
python 04_testing/test_matching_accuracy.py

# Run integration tests
cd .. && pytest tests/test_nvd_integration.py -v
```

All tests should pass:
```
✅ ALL TESTS PASSED (4/4)
```

## 💡 Tips

1. **Start with basic examples** - Don't jump to scanning immediately
2. **Use API key** - Makes everything much faster
3. **Build local database** - Essential for production use
4. **Review match_reason** - Understand why packages matched
5. **Adjust confidence** - Balance false positives vs false negatives
6. **Check output directory** - All reports saved to `output/`

## 🤝 Contributing

Found a bug or have an improvement?

1. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) first
2. Run tests: `python 04_testing/test_matching_accuracy.py`
3. Report issues with:
   - Error message
   - Python/Docker versions
   - Minimal reproducer

## 🔗 Next Steps

After exploring examples:

1. ✅ Run basic examples
2. ✅ Complete your first vulnerability scan
3. ✅ Understand the matching algorithm
4. → Build custom scanning workflows
5. → Integrate into CI/CD
6. → Deploy to production

## 📊 Quick Reference

```bash
# Basic operations
python 01_basic/docker_usage.py              # Analyze Docker image
python 01_basic/nvd_basic_usage.py           # Fetch CVEs
python 01_basic/cve_database_usage.py        # Build database

# Vulnerability scanning
python 03_vulnerability_scanning/demo_with_findings.py  # Best starting point
python 03_vulnerability_scanning/scan_vulnerable_image.py
python 03_vulnerability_scanning/docker_vulnerability_scan.py

# Testing & validation
python 04_testing/test_matching_accuracy.py  # Run tests
python 04_testing/debug_matching.py          # Debug matching

# Advanced features
python 02_advanced/docker_advanced.py        # Batch analysis
python 02_advanced/python_sbom_example.py    # Generate SBOM
python 02_advanced/cve_matching_example.py   # Understand algorithms
```

---

**Ready to get started?** Head to [01_basic/](01_basic/) or try the recommended first scan:

```bash
python 03_vulnerability_scanning/demo_with_findings.py
```
