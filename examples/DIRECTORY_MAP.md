# Examples Directory Map

Visual guide to navigate the examples folder.

```
examples/
│
├── 📖 Documentation
│   ├── START_HERE.md ...................... ⭐ NEW USERS START HERE!
│   ├── README.md .......................... Main examples guide
│   ├── CLI_EXAMPLES.md .................... CLI command reference
│   ├── INDEX.md ........................... Detailed navigation
│   └── TROUBLESHOOTING.md ................. Common problems & solutions
│
├── 📁 01_basic/ ........................... BEGINNER (10 min)
│   ├── README.md
│   ├── docker_usage.py .................... Docker container analysis
│   ├── nvd_basic_usage.py ................. Fetch CVEs from NVD
│   ├── cve_database_usage.py .............. Local CVE database
│   └── hash_usage.py ...................... File hashing
│
├── 📁 02_advanced/ ........................ INTERMEDIATE (30 min)
│   ├── README.md
│   ├── docker_advanced.py ................. Batch analysis, comparisons
│   ├── python_sbom_example.py ............. Generate SBOM
│   ├── cve_matching_example.py ............ Matching algorithms
│   └── docker_cli_examples.sh ............. CLI workflows
│
├── 📁 03_vulnerability_scanning/ .......... MAIN FEATURE! ⭐ (5-10 min)
│   ├── README.md
│   ├── demo_with_findings.py .............. ⭐ Recommended first scan
│   ├── scan_vulnerable_image.py ........... Scan Ubuntu 18.04
│   ├── docker_vulnerability_scan.py ....... 6 comprehensive examples
│   └── quick_vulnerability_demo.py ........ Quick demo (no API key)
│
├── 📁 04_testing/ ......................... VALIDATION (5 min)
│   ├── README.md
│   ├── test_matching_accuracy.py .......... ✅ Test suite (run this!)
│   └── debug_matching.py .................. Debug tool
│
└── 📁 output/ ............................. Generated files (gitignored)
    ├── *.json ............................. Vulnerability reports
    ├── *.txt .............................. Summary reports
    └── *_analysis.json .................... Container analysis
```

## 🎯 Quick Navigation

### By Goal

**I want to scan for vulnerabilities NOW:**
→ `03_vulnerability_scanning/demo_with_findings.py`

**I'm learning the basics:**
→ `01_basic/docker_usage.py` → `01_basic/nvd_basic_usage.py`

**I need to generate an SBOM:**
→ `02_advanced/python_sbom_example.py`

**I found a bug / false positive:**
→ `04_testing/debug_matching.py`

**I'm integrating into CI/CD:**
→ `CLI_EXAMPLES.md`

### By Experience Level

**Never used Threat Radar before:**
1. Read `START_HERE.md`
2. Run `01_basic/docker_usage.py`
3. Run `03_vulnerability_scanning/demo_with_findings.py`

**Used basic features, want more:**
1. Explore `02_advanced/`
2. Read `CLI_EXAMPLES.md`
3. Study `02_advanced/cve_matching_example.py`

**Building production tools:**
1. Complete all examples in order
2. Read `../MATCHING_IMPROVEMENTS.md`
3. Review `CLI_EXAMPLES.md` workflows
4. Study `04_testing/` for validation

### By Time Available

**5 minutes:**
```bash
python 03_vulnerability_scanning/quick_vulnerability_demo.py
```

**30 minutes:**
```bash
# Complete beginner track
python 01_basic/docker_usage.py
python 01_basic/nvd_basic_usage.py
python 03_vulnerability_scanning/demo_with_findings.py
```

**2 hours:**
```bash
# Complete all basic examples
cd 01_basic && for f in *.py; do python "$f"; done

# Run comprehensive scan
cd ../03_vulnerability_scanning
python docker_vulnerability_scan.py
```

## 📊 File Size Guide

| File | Lines | Complexity | Time to Read |
|------|-------|------------|--------------|
| `docker_usage.py` | 200 | Low | 5 min |
| `nvd_basic_usage.py` | 230 | Low | 5 min |
| `cve_database_usage.py` | 250 | Medium | 10 min |
| `demo_with_findings.py` | 300 | Medium | 10 min |
| `docker_vulnerability_scan.py` | 350 | High | 20 min |
| `test_matching_accuracy.py` | 200 | Medium | 10 min |

## 🎓 Learning Dependencies

```
                    ┌─────────────────────┐
                    │  START_HERE.md      │
                    └──────────┬──────────┘
                               │
                ┌──────────────┼──────────────┐
                │              │              │
                ▼              ▼              ▼
        ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
        │  01_basic/  │ │ 04_testing/ │ │03_vuln_scan/│
        │             │ │             │ │             │
        │ Foundation  │ │ Validation  │ │ Quick Start │
        └──────┬──────┘ └─────────────┘ └──────┬──────┘
               │                               │
               └──────────┬────────────────────┘
                          │
                          ▼
                  ┌──────────────┐
                  │ 02_advanced/ │
                  │              │
                  │ Deep Dive    │
                  └──────┬───────┘
                         │
                         ▼
                  ┌──────────────┐
                  │  Production  │
                  │  Integration │
                  └──────────────┘
```

## 🗺️ Full Navigation Map

```
Examples Journey
│
├── START → Read START_HERE.md
│
├── VALIDATE → Run 04_testing/test_matching_accuracy.py
│            (Ensure system works)
│
├── QUICK WIN → Run 03_vulnerability_scanning/demo_with_findings.py
│             (See immediate results!)
│
├── LEARN BASICS → Complete 01_basic/
│   ├── docker_usage.py
│   ├── nvd_basic_usage.py
│   ├── cve_database_usage.py
│   └── hash_usage.py
│
├── GO DEEPER → Explore 02_advanced/
│   ├── docker_advanced.py
│   ├── python_sbom_example.py
│   └── cve_matching_example.py
│
├── MASTER SCANNING → Work through 03_vulnerability_scanning/
│   ├── quick_vulnerability_demo.py
│   ├── demo_with_findings.py
│   ├── scan_vulnerable_image.py
│   └── docker_vulnerability_scan.py (all 6 examples)
│
└── PRODUCTION → Study documentation
    ├── CLI_EXAMPLES.md
    ├── ../MATCHING_IMPROVEMENTS.md
    └── Build custom workflows
```

## 📝 Example Template

When creating new examples, use this structure:

```python
"""
Brief description of what this example demonstrates.

This example shows:
- Feature 1
- Feature 2
- Feature 3
"""

# Step 1: Setup
print("Step 1: Description...")
# code

# Step 2: Main operation
print("Step 2: Description...")
# code

# Step 3: Results
print("Step 3: Description...")
# code

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️  Interrupted")
    except Exception as e:
        print(f"\n❌ Error: {e}")
```

## 🔗 Related Files

- `../CLAUDE.md` - Development guide for contributors
- `../README.md` - Main project documentation
- `../MATCHING_IMPROVEMENTS.md` - Algorithm improvements documentation
- `../tests/` - Pytest integration tests

---

**Lost?** Go back to [START_HERE.md](START_HERE.md)

**Need help?** Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

**Ready to code?** Pick a directory and dive in!
