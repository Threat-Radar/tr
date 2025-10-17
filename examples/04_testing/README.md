# Testing & Validation Examples

Tools for testing, debugging, and validating CVE matching accuracy in the legacy NVD-based system.

**Note:** These tests validate the legacy package name matching logic. Modern Grype-based scanning uses Grype's battle-tested matching engine.

## Examples Overview

| Example | What It Does | Time | Purpose |
|---------|--------------|------|---------|
| `test_matching_accuracy.py` | Validate package matching | <1 min | Ensure matching accuracy |
| `debug_matching.py` | Debug specific CVE matches | ~1 min | Troubleshooting |

## Quick Start

```bash
# Run all validation tests
python test_matching_accuracy.py

# Expected output:
# ✅ ALL TESTS PASSED (4/4)
```

## Example Details

### 1. Matching Accuracy Tests ⭐

**File:** `test_matching_accuracy.py`

Comprehensive test suite validating package name matching logic for the legacy system.

```bash
python test_matching_accuracy.py
```

**What it tests:**
- ✓ Legitimate package matches (openssl ↔ libssl, glibc ↔ libc6)
- ✓ False positive prevention (dash ≠ bash, gzip ≠ grep)
- ✓ Edge cases (short names, prefixes, case sensitivity)
- ✓ Blacklist enforcement

**Expected output:**
```
✅ ALL TESTS PASSED (4/4)

✓ PASS - Legitimate Matches (10/10)
✓ PASS - False Positive Prevention (8/8)
✓ PASS - Edge Cases (6/6)
✓ PASS - Blacklist Enforcement (6/6)
```

### 2. Debug Matching

**File:** `debug_matching.py`

Debug tool to understand why packages match or don't match specific CVEs in the legacy system.

```bash
python debug_matching.py
```

**Features:**
- Fetches Shellshock CVE as example
- Tests multiple bash versions
- Shows CPE parsing
- Displays version comparison logic
- Explains confidence scoring

**Use cases:**
- Understanding legacy matching algorithm
- Debugging false positives in historical scans
- Learning the old CVE matching system

## Modern Testing Approach

For Grype-based scanning (recommended), testing is handled by Grype itself:

```bash
# Scan image with Grype
threat-radar cve scan-image alpine:3.18 -o scan.json

# Review results (Grype's matching is pre-validated)
cat scan.json | jq '.matches[] | {vuln: .vulnerability.id, package: .artifact.name}'

# Generate report to verify findings
threat-radar report generate scan.json -o report.html -f html
```

## Test Coverage (Legacy System)

Current test coverage for the legacy NVD-based matcher:

| Component | Tests | Status |
|-----------|-------|--------|
| Package name matching | 30 | ✅ All passing |
| Version comparison | 15 | ✅ All passing |
| Version range checking | 10 | ✅ All passing |
| Confidence scoring | 8 | ✅ All passing |
| Blacklist enforcement | 6 | ✅ All passing |

## Understanding Test Results

### Test 1: Legitimate Matches

Validates known package variants correctly match:
```
✓ openssl vs libssl: 0.90 (>= 0.9)
✓ glibc vs libc6: 0.90 (>= 0.9)
```

### Test 2: False Positive Prevention

Ensures unrelated packages don't match:
```
✓ dash vs bash: 0.00 (< 0.5)
✓ gzip vs grep: 0.00 (< 0.5)
```

### Test 3: Edge Cases

Tests special scenarios:
```
✓ libpng vs png: 0.95 - lib prefix stripped
✓ BASH vs bash: 1.00 - exact match ignoring case
```

### Test 4: Blacklist Enforcement

Verifies blacklisted pairs return 0.0:
```
✓ bash vs dash: 0.00 (blacklisted)
```

## Running Tests in CI/CD

These tests can be run in continuous integration:

```bash
#!/bin/bash
# In your CI pipeline (legacy system validation)

# Run validation tests
python examples/04_testing/test_matching_accuracy.py

# Exit with error if tests fail
if [ $? -ne 0 ]; then
  echo "❌ Matching accuracy tests failed"
  exit 1
fi

echo "✅ All tests passed"
```

## Prerequisites

- Python 3.8+
- No external dependencies for `test_matching_accuracy.py`
- Internet connection for `debug_matching.py` (fetches CVE data)

## Next Steps

**For Modern Workflows:**
- Use Grype-based scanning: `threat-radar cve scan-image`
- See [../README.md](../README.md) for complete documentation

**For Legacy System:**
- Study test code to understand matching logic
- Review [../../threat_radar/core/cve_matcher.py](../../threat_radar/core/cve_matcher.py) for implementation details

## Documentation

- **[Main Examples Guide](../README.md)** - Complete examples overview
- **[CLI Reference](../../CLAUDE.md)** - Full command documentation
- **[Matching Improvements](../../MATCHING_IMPROVEMENTS.md)** - Legacy algorithm details
- **[Integration Tests](../../tests/test_nvd_integration.py)** - Additional tests

---

**Quick command:** `python test_matching_accuracy.py`
