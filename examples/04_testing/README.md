# Testing & Validation Examples

Tools for testing, debugging, and validating CVE matching accuracy.

## Examples

### 1. Matching Accuracy Tests
**File:** `test_matching_accuracy.py`

Comprehensive test suite validating package name matching logic.

```bash
python test_matching_accuracy.py
```

**What it tests:**
- ✓ Legitimate package matches (openssl ↔ libssl, etc.)
- ✓ False positive prevention (dash ≠ bash, etc.)
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

**Time:** <1 minute

---

### 2. Debug Matching
**File:** `debug_matching.py`

Debug tool to understand why packages match or don't match specific CVEs.

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
- Understanding why a package matched
- Debugging false positives
- Learning the matching algorithm
- Testing version comparison

**Time:** ~1 minute

---

## Running Tests

### Quick Validation

```bash
# Run all tests
python test_matching_accuracy.py

# Should see all tests passing
```

### Debug Specific Match

Edit `debug_matching.py` to test your specific case:

```python
# Test your package
packages = [
    Package(name="your-package", version="1.2.3", architecture="amd64"),
]

# Fetch your CVE
cve = client.get_cve_by_id("CVE-YYYY-XXXXX")

# See matching details
matches = matcher.match_package(packages[0], [cve])
```

## Understanding Test Results

### Test 1: Legitimate Matches

Validates that known package variants correctly match:

```
✓ openssl vs libssl: 0.90 (>= 0.9)
✓ glibc vs libc6: 0.90 (>= 0.9)
```

**If these fail:** Package mappings may be broken. Check `NAME_MAPPINGS` in `cve_matcher.py`.

### Test 2: False Positive Prevention

Ensures unrelated packages don't match:

```
✓ dash vs bash: 0.00 (< 0.5)
✓ gzip vs grep: 0.00 (< 0.5)
```

**If these fail:** Blacklist or short name penalty may be broken. Check `NEVER_MATCH` and similarity calculation.

### Test 3: Edge Cases

Tests special scenarios:

```
✓ libpng vs png: 0.95 - lib prefix should be stripped
✓ BASH vs bash: 1.00 - exact match ignoring case
```

**If these fail:** Name normalization may have issues. Check `normalize_name()` function.

### Test 4: Blacklist Enforcement

Verifies blacklisted pairs return 0.0:

```
✓ bash vs dash: 0.00 (blacklisted)
```

**If these fail:** Blacklist checking is broken. Verify `similarity_score()` checks `NEVER_MATCH`.

## Debugging Workflow

When you encounter an unexpected match:

1. **Run the test suite:**
   ```bash
   python test_matching_accuracy.py
   ```

2. **If tests pass but you see issues in scanning:**
   - Use `debug_matching.py` to investigate specific CVE
   - Check confidence threshold in your scan
   - Review match_reason in the report

3. **If tests fail:**
   - Check recent code changes to `cve_matcher.py`
   - Verify `NAME_MAPPINGS` and `NEVER_MATCH` are correct
   - Run individual test functions to isolate issue

## Adding New Tests

### Test a New Package Mapping

```python
# In test_matching_accuracy.py, add to legitimate matches:
test_cases = [
    # ... existing tests ...
    ('your-package', 'your-variant', 0.90),
]
```

### Test a New False Positive

```python
# In test_matching_accuracy.py, add to false positives:
test_cases = [
    # ... existing tests ...
    ('package-a', 'package-b'),  # Should NOT match
]
```

### Add to Blacklist

If you discover a false positive that should never match:

```python
# In threat_radar/core/cve_matcher.py
NEVER_MATCH = {
    # ... existing entries ...
    frozenset(["package-a", "package-b"]),
}
```

Then verify with:
```bash
python test_matching_accuracy.py
```

## Performance Testing

### Measure Matching Speed

```python
import time
from threat_radar.core.cve_matcher import CVEMatcher

matcher = CVEMatcher()

start = time.time()
matches = matcher.bulk_match_packages(packages, cves)
elapsed = time.time() - start

print(f"Matched {len(packages)} packages against {len(cves)} CVEs")
print(f"Time: {elapsed:.2f}s")
print(f"Rate: {len(packages) * len(cves) / elapsed:.0f} comparisons/sec")
```

Expected performance:
- ~10,000 comparisons/second on modern hardware
- 200 packages × 50 CVEs = ~1 second

## Test Coverage

Current test coverage:

| Component | Tests | Status |
|-----------|-------|--------|
| Package name matching | 30 | ✅ All passing |
| Version comparison | 15 | ✅ All passing |
| Version range checking | 10 | ✅ All passing |
| Confidence scoring | 8 | ✅ All passing |
| Blacklist enforcement | 6 | ✅ All passing |

## Continuous Integration

These tests can be run in CI/CD:

```bash
#!/bin/bash
# In your CI pipeline

# Run validation tests
python examples/04_testing/test_matching_accuracy.py

# Exit with error if tests fail
if [ $? -ne 0 ]; then
  echo "❌ Matching accuracy tests failed"
  exit 1
fi

echo "✅ All tests passed"
```

## Related Documentation

- **[MATCHING_IMPROVEMENTS.md](../../MATCHING_IMPROVEMENTS.md)** - Algorithm details and improvements
- **[CVE Matcher Code](../../threat_radar/core/cve_matcher.py)** - Implementation
- **[Integration Tests](../../tests/test_nvd_integration.py)** - Full integration tests

## Contributing

When adding new matching logic:

1. **Write tests first** in `test_matching_accuracy.py`
2. **Run tests** to verify they fail (red)
3. **Implement** your changes in `cve_matcher.py`
4. **Run tests** to verify they pass (green)
5. **Add edge cases** to prevent regressions

This ensures the matcher remains accurate and reliable.
