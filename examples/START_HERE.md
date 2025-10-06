# 🚀 Start Here!

Welcome to Threat Radar examples! This guide will get you up and running in 5 minutes.

## ⚡ Quickest Start (3 commands)

```bash
# 1. Install Threat Radar
pip install -e ..

# 2. Test it works
python 04_testing/test_matching_accuracy.py

# 3. See real vulnerabilities!
python 03_vulnerability_scanning/demo_with_findings.py
```

## 📁 What's in Each Directory?

### [01_basic/](01_basic/) - Start Here! (10 minutes)
Learn the fundamentals:
- Analyze Docker images
- Fetch CVEs from NVD
- Build local database
- Hash files

**Start with:** `python 01_basic/docker_usage.py`

### [02_advanced/](02_advanced/) - Go Deeper (30 minutes)
Advanced features:
- Batch image analysis
- SBOM generation
- Matching algorithms
- CLI workflows

**Try:** `python 02_advanced/cve_matching_example.py`

### [03_vulnerability_scanning/](03_vulnerability_scanning/) - The Main Event! ⭐
Complete vulnerability scanning:
- Real CVE detection
- Multiple scanning workflows
- Detailed reports

**Recommended:** `python 03_vulnerability_scanning/demo_with_findings.py`

### [04_testing/](04_testing/) - Validate (5 minutes)
Test and debug:
- Accuracy tests
- Debug tools

**Run:** `python 04_testing/test_matching_accuracy.py`

## 🎯 Choose Your Path

### Path 1: I Want to Scan NOW! (5 minutes)
```bash
# Skip straight to vulnerability scanning
python 03_vulnerability_scanning/demo_with_findings.py

# Read the results, then learn the basics
```

### Path 2: Learn Step-by-Step (30 minutes)
```bash
# Day 1: Basics
python 01_basic/docker_usage.py
python 01_basic/nvd_basic_usage.py

# Day 2: Scan
python 03_vulnerability_scanning/demo_with_findings.py

# Day 3: Understand
python 02_advanced/cve_matching_example.py
python 04_testing/test_matching_accuracy.py
```

### Path 3: I'm Building Production Tools (2 hours)
```bash
# 1. Complete all basic examples
cd 01_basic && ls *.py | xargs -I {} python {}

# 2. Study advanced examples
cd ../02_advanced && ls *.py | xargs -I {} python {}

# 3. Review all scanning workflows
cd ../03_vulnerability_scanning
python docker_vulnerability_scan.py

# 4. Read documentation
cat ../CLI_EXAMPLES.md
cat ../../MATCHING_IMPROVEMENTS.md
```

## 🎓 Learning Checklist

- [ ] Run `01_basic/docker_usage.py` - Understand Docker analysis
- [ ] Run `01_basic/nvd_basic_usage.py` - Fetch a CVE
- [ ] Run `03_vulnerability_scanning/demo_with_findings.py` - See real vulnerabilities
- [ ] Run `04_testing/test_matching_accuracy.py` - Validate system
- [ ] Read `CLI_EXAMPLES.md` - Learn CLI commands
- [ ] Try scanning your own Docker image
- [ ] Understand confidence scores and match reasons

## 💡 Pro Tips

1. **Get an NVD API Key** (free!)
   - Without: 5 requests/30s (slow)
   - With: 50 requests/30s (10x faster!)
   - Get here: https://nvd.nist.gov/developers/request-an-api-key

2. **Build Local Database First**
   ```bash
   threat-radar cve update --days 90
   ```
   Then all queries are instant!

3. **Start with Older Images**
   - `ubuntu:14.04` - Guaranteed vulnerabilities
   - `ubuntu:18.04` - Some vulnerabilities
   - `ubuntu:22.04` - Fewer/no vulnerabilities

4. **Understand Confidence Scores**
   - 1.0 = Exact match (100% certain)
   - 0.9 = Known variant (very confident)
   - 0.7 = Good match (default threshold)
   - 0.6 = Lower confidence (may need review)

## 🆘 Getting Stuck?

**Docker not running?**
```bash
docker ps  # Check if Docker is running
open -a Docker  # Start Docker Desktop (macOS)
```

**Rate limits?**
```bash
# Get an API key or use local database
threat-radar cve update --days 30
```

**No vulnerabilities found?**
```bash
# Try an older image
python 03_vulnerability_scanning/demo_with_findings.py
```

**Full troubleshooting:** [TROUBLESHOOTING.md](TROUBLESHOOTING.md)

## 📚 Documentation Map

```
examples/
├── START_HERE.md  ← You are here!
├── README.md      ← Full examples guide
├── CLI_EXAMPLES.md ← CLI command reference
├── INDEX.md       ← Detailed navigation
└── TROUBLESHOOTING.md ← Common issues
```

## ✅ First Success

Your first successful scan should look like this:

```
======================================================================
VULNERABILITY SCAN: Ubuntu 14.04 (Known Vulnerable Packages)
======================================================================

✓ Found 9 vulnerable packages
✓ Total vulnerabilities detected: 15

Severity Breakdown:
  HIGH    : 10
  MEDIUM  :  3
  LOW     :  2

📄 Detailed report saved to: output/ubuntu_14.04_vulnerability_report.json

✅ SCAN COMPLETE
```

## 🚀 Next Actions

After your first scan:

1. ✅ Read the JSON report (in `output/` directory)
2. ✅ Understand match_reason field
3. ✅ Check confidence scores
4. ✅ Try scanning your own images
5. → Build custom workflows
6. → Integrate into CI/CD

## 🎯 Quick Commands

```bash
# Validate installation
python 04_testing/test_matching_accuracy.py

# First scan (recommended)
python 03_vulnerability_scanning/demo_with_findings.py

# Learn basics
python 01_basic/docker_usage.py

# Advanced features
python 02_advanced/cve_matching_example.py

# Get help
threat-radar --help
```

---

**Ready?** Pick a path above and start coding!

For the impatient: `python 03_vulnerability_scanning/demo_with_findings.py` 🎯
