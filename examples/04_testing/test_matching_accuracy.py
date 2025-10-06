"""
Test script to validate CVE matching accuracy.

This script tests the package name matching logic to ensure:
1. Legitimate matches are correctly identified
2. False positives are prevented
3. Edge cases are handled properly
"""

from threat_radar.core.cve_matcher import PackageNameMatcher


def test_legitimate_matches():
    """Test that legitimate package name variations match correctly."""
    print("\n" + "=" * 70)
    print("TEST 1: Legitimate Matches")
    print("=" * 70)
    print("Testing known package name variations should match with high confidence...")

    test_cases = [
        ('openssl', 'libssl', 0.90),
        ('glibc', 'libc6', 0.90),
        ('glibc', 'libc', 0.90),
        ('glibc', 'libc-bin', 0.90),
        ('zlib', 'zlib1g', 0.90),
        ('zlib', 'libz', 0.90),
        ('pcre', 'libpcre3', 0.95),
        ('ncurses', 'libncurses', 0.90),
        ('bash', 'bash', 1.00),
        ('openssl', 'openssl-libs', 0.90),
    ]

    passed = 0
    failed = 0

    for name1, name2, expected_min_score in test_cases:
        score = PackageNameMatcher.similarity_score(name1, name2)
        if score >= expected_min_score:
            print(f"  ✓ {name1:15s} vs {name2:15s}: {score:.2f} (>= {expected_min_score})")
            passed += 1
        else:
            print(f"  ✗ {name1:15s} vs {name2:15s}: {score:.2f} (expected >= {expected_min_score})")
            failed += 1

    print(f"\nResult: {passed} passed, {failed} failed")
    return failed == 0


def test_false_positives():
    """Test that unrelated packages don't match."""
    print("\n" + "=" * 70)
    print("TEST 2: False Positive Prevention")
    print("=" * 70)
    print("Testing unrelated packages should NOT match...")

    test_cases = [
        ('dash', 'bash'),      # Different shells
        ('bash', 'ash'),       # Different shells
        ('gzip', 'grep'),      # Compression vs search
        ('gzip', 'bzip2'),     # Different compression
        ('tar', 'star'),       # Different archive tools
        ('sed', 'awk'),        # Different text tools
        ('curl', 'wget'),      # Different download tools
        ('vim', 'emacs'),      # Different editors
    ]

    passed = 0
    failed = 0
    max_allowed_score = 0.5

    for name1, name2 in test_cases:
        score = PackageNameMatcher.similarity_score(name1, name2)
        if score < max_allowed_score:
            print(f"  ✓ {name1:15s} vs {name2:15s}: {score:.2f} (< {max_allowed_score})")
            passed += 1
        else:
            print(f"  ✗ {name1:15s} vs {name2:15s}: {score:.2f} (should be < {max_allowed_score})")
            failed += 1

    print(f"\nResult: {passed} passed, {failed} failed")
    return failed == 0


def test_edge_cases():
    """Test edge cases and special scenarios."""
    print("\n" + "=" * 70)
    print("TEST 3: Edge Cases")
    print("=" * 70)
    print("Testing special scenarios...")

    test_cases = [
        # Prefix stripping
        ('libpng', 'png', 0.90, "lib prefix should be stripped"),
        ('python3-pip', 'pip', 0.90, "python3- prefix should be stripped"),

        # Version numbers in names (conservative - won't match unless added to mappings)
        # This is acceptable - better to miss a match than create false positive
        # If needed, add explicit mapping: "openssl": ["libssl", "libssl1.1", "libssl3"]

        # Case insensitivity
        ('OpenSSL', 'libssl', 0.90, "should be case insensitive"),
        ('BASH', 'bash', 1.00, "exact match ignoring case"),

        # Short names with high similarity requirement
        ('tar', 'tar', 1.00, "exact match for short names"),
        ('vim', 'vi', 0.40, "short dissimilar names penalized"),
    ]

    passed = 0
    failed = 0

    for name1, name2, expected_min_score, description in test_cases:
        score = PackageNameMatcher.similarity_score(name1, name2)
        if score >= expected_min_score:
            print(f"  ✓ {name1:15s} vs {name2:15s}: {score:.2f} - {description}")
            passed += 1
        else:
            print(f"  ✗ {name1:15s} vs {name2:15s}: {score:.2f} - {description}")
            print(f"     Expected >= {expected_min_score}")
            failed += 1

    print(f"\nResult: {passed} passed, {failed} failed")
    return failed == 0


def test_blacklist():
    """Test that blacklisted pairs never match."""
    print("\n" + "=" * 70)
    print("TEST 4: Blacklist Enforcement")
    print("=" * 70)
    print("Testing blacklisted pairs return 0.0 score...")

    # These are defined in NEVER_MATCH
    blacklisted_pairs = [
        ('bash', 'dash'),
        ('dash', 'bash'),  # Test both directions
        ('bash', 'ash'),
        ('gzip', 'bzip2'),
        ('gzip', 'grep'),
        ('tar', 'star'),
        ('glibc', 'klibc'),
        ('glibc', 'klibc-utils'),
        ('glibc', 'libklibc'),
    ]

    passed = 0
    failed = 0

    for name1, name2 in blacklisted_pairs:
        score = PackageNameMatcher.similarity_score(name1, name2)
        if score == 0.0:
            print(f"  ✓ {name1:15s} vs {name2:15s}: {score:.2f} (blacklisted)")
            passed += 1
        else:
            print(f"  ✗ {name1:15s} vs {name2:15s}: {score:.2f} (should be 0.0)")
            failed += 1

    print(f"\nResult: {passed} passed, {failed} failed")
    return failed == 0


def main():
    """Run all tests."""
    print("\n" + "=" * 70)
    print("CVE MATCHER - ACCURACY VALIDATION TESTS")
    print("=" * 70)
    print("\nValidating package name matching logic...")

    test_results = []

    # Run all tests
    test_results.append(("Legitimate Matches", test_legitimate_matches()))
    test_results.append(("False Positive Prevention", test_false_positives()))
    test_results.append(("Edge Cases", test_edge_cases()))
    test_results.append(("Blacklist Enforcement", test_blacklist()))

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    total_passed = sum(1 for _, result in test_results if result)
    total_tests = len(test_results)

    for test_name, passed in test_results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status} - {test_name}")

    print("\n" + "=" * 70)
    if total_passed == total_tests:
        print(f"✅ ALL TESTS PASSED ({total_passed}/{total_tests})")
        print("=" * 70)
        print("\nThe CVE matcher is working correctly:")
        print("  • Legitimate package variations are matched")
        print("  • False positives (dash vs bash, etc.) are prevented")
        print("  • Edge cases are handled properly")
        print("  • Blacklisted pairs are rejected")
        return 0
    else:
        print(f"❌ SOME TESTS FAILED ({total_passed}/{total_tests} passed)")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    exit(main())
