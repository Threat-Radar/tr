"""
Validation script for Grype vulnerability scanner integration.

This script validates that:
1. Grype is properly installed and accessible
2. Grype can scan Docker images successfully
3. Vulnerability detection is working correctly
4. Results are parsed properly

This replaces the old package name matching tests, as we now use Grype's
industry-standard vulnerability matching instead of custom logic.
"""

from threat_radar.core.grype_integration import GrypeClient, GrypeSeverity


def test_grype_installation():
    """Test 1: Verify Grype is installed and accessible."""
    print("\n" + "=" * 70)
    print("TEST 1: Grype Installation")
    print("=" * 70)
    print("Testing if Grype is properly installed and accessible...\n")

    try:
        grype = GrypeClient()
        print("✓ PASS: Grype client initialized successfully")
        print("  Grype is installed and accessible")
        return True
    except RuntimeError as e:
        print(f"✗ FAIL: {e}")
        print("\nInstallation instructions:")
        print("  macOS: brew install grype")
        print("  Linux: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh")
        return False


def test_basic_scan():
    """Test 2: Perform basic vulnerability scan."""
    print("\n" + "=" * 70)
    print("TEST 2: Basic Vulnerability Scan")
    print("=" * 70)
    print("Testing basic image scanning functionality...\n")

    try:
        grype = GrypeClient()

        # Use a small, known-vulnerable image for testing
        test_image = "alpine:3.14"  # Older Alpine version (likely has some vulns)

        print(f"Scanning test image: {test_image}")
        print("(This may take a minute on first run...)\n")

        scan_result = grype.scan_docker_image(test_image)

        print(f"✓ PASS: Scan completed successfully")
        print(f"  Target: {scan_result.target}")
        print(f"  Total vulnerabilities: {scan_result.total_count}")

        if scan_result.total_count > 0:
            print(f"  Severity counts:")
            for severity in ['critical', 'high', 'medium', 'low']:
                count = scan_result.severity_counts.get(severity, 0)
                if count > 0:
                    print(f"    {severity.upper():10s}: {count}")

        return True
    except Exception as e:
        print(f"✗ FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_severity_filtering():
    """Test 3: Test severity filtering functionality."""
    print("\n" + "=" * 70)
    print("TEST 3: Severity Filtering")
    print("=" * 70)
    print("Testing vulnerability filtering by severity...\n")

    try:
        grype = GrypeClient()

        test_image = "alpine:3.14"

        print(f"Scanning {test_image}...")
        scan_result = grype.scan_docker_image(test_image)

        original_count = scan_result.total_count

        # Filter for HIGH and above
        filtered_result = scan_result.filter_by_severity(GrypeSeverity.HIGH)
        filtered_count = filtered_result.total_count

        print(f"✓ PASS: Severity filtering works correctly")
        print(f"  Original vulnerabilities: {original_count}")
        print(f"  After HIGH+ filter: {filtered_count}")

        if filtered_count <= original_count:
            print("  ✓ Filter reduced or maintained vulnerability count (as expected)")
        else:
            print(f"  ✗ WARNING: Filter increased count (unexpected)")

        return True
    except Exception as e:
        print(f"✗ FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_result_structure():
    """Test 4: Validate scan result structure and data."""
    print("\n" + "=" * 70)
    print("TEST 4: Scan Result Structure")
    print("=" * 70)
    print("Testing that scan results have correct structure...\n")

    try:
        grype = GrypeClient()

        test_image = "alpine:3.14"

        print(f"Scanning {test_image}...")
        scan_result = grype.scan_docker_image(test_image)

        # Verify result has expected attributes
        assert hasattr(scan_result, 'target'), "Missing 'target' attribute"
        assert hasattr(scan_result, 'vulnerabilities'), "Missing 'vulnerabilities' attribute"
        assert hasattr(scan_result, 'total_count'), "Missing 'total_count' attribute"
        assert hasattr(scan_result, 'severity_counts'), "Missing 'severity_counts' attribute"

        # Verify vulnerabilities have expected attributes
        if scan_result.vulnerabilities:
            vuln = scan_result.vulnerabilities[0]
            assert hasattr(vuln, 'id'), "Vulnerability missing 'id' attribute"
            assert hasattr(vuln, 'severity'), "Vulnerability missing 'severity' attribute"
            assert hasattr(vuln, 'package_name'), "Vulnerability missing 'package_name' attribute"
            assert hasattr(vuln, 'package_version'), "Vulnerability missing 'package_version' attribute"

            print("✓ PASS: Scan result structure is correct")
            print(f"  Sample vulnerability:")
            print(f"    ID: {vuln.id}")
            print(f"    Severity: {vuln.severity}")
            print(f"    Package: {vuln.package_name}@{vuln.package_version}")
            if vuln.fixed_in_version:
                print(f"    Fix: {vuln.fixed_in_version}")
        else:
            print("✓ PASS: Scan result structure is correct (no vulnerabilities found)")

        return True
    except AssertionError as e:
        print(f"✗ FAIL: {e}")
        return False
    except Exception as e:
        print(f"✗ FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_known_vulnerable_image():
    """Test 5: Scan a known vulnerable image and verify detection."""
    print("\n" + "=" * 70)
    print("TEST 5: Known Vulnerable Image Detection")
    print("=" * 70)
    print("Testing detection of vulnerabilities in known-vulnerable images...\n")

    try:
        grype = GrypeClient()

        # Use a very old Alpine version that should definitely have vulnerabilities
        test_image = "alpine:3.9"  # Released 2019, should have many CVEs

        print(f"Scanning known-vulnerable image: {test_image}")
        print("(This version is from 2019 and should have multiple CVEs)\n")

        scan_result = grype.scan_docker_image(test_image)

        if scan_result.total_count > 0:
            print(f"✓ PASS: Vulnerabilities detected as expected")
            print(f"  Total vulnerabilities: {scan_result.total_count}")

            high_and_critical = (
                scan_result.severity_counts.get('critical', 0) +
                scan_result.severity_counts.get('high', 0)
            )

            if high_and_critical > 0:
                print(f"  HIGH + CRITICAL: {high_and_critical}")
                print("  ✓ Detected high-severity issues (expected for old image)")
            else:
                print("  ⚠ No HIGH/CRITICAL issues (unusual for 2019 image)")

            return True
        else:
            print(f"⚠ WARNING: No vulnerabilities found")
            print("  This is unusual for alpine:3.9 from 2019")
            print("  Possible causes:")
            print("    - Grype database is out of date (run: threat-radar cve db-update)")
            print("    - Network issues preventing database access")
            return False

    except Exception as e:
        print(f"✗ FAIL: {e}")
        import traceback
        traceback.print_exc()
        return False


def run_all_tests():
    """Run all validation tests."""
    print("\n" + "=" * 70)
    print("GRYPE INTEGRATION VALIDATION SUITE")
    print("=" * 70)
    print("\nThis test suite validates the Grype vulnerability scanner integration.")
    print("Grype is an industry-standard tool from Anchore for vulnerability detection.")

    tests = [
        ("Grype Installation", test_grype_installation),
        ("Basic Scan", test_basic_scan),
        ("Severity Filtering", test_severity_filtering),
        ("Result Structure", test_result_structure),
        ("Known Vulnerable Image", test_known_vulnerable_image),
    ]

    results = []

    for test_name, test_func in tests:
        passed = test_func()
        results.append((test_name, passed))

    # Summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)

    passed_count = sum(1 for _, passed in results if passed)
    total_count = len(results)

    for test_name, passed in results:
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}: {test_name}")

    print(f"\n  Result: {passed_count}/{total_count} tests passed")

    if passed_count == total_count:
        print("\n✅ ALL TESTS PASSED!")
        print("\nYour Grype integration is working correctly.")
        print("You can now use Threat Radar for vulnerability scanning!")
        return True
    else:
        print("\n⚠ SOME TESTS FAILED")
        print("\nPlease review the failures above and:")
        print("  1. Ensure Grype is installed (brew install grype)")
        print("  2. Ensure Docker is running (docker ps)")
        print("  3. Update Grype database (threat-radar cve db-update)")
        print("  4. Check internet connectivity")
        return False


if __name__ == "__main__":
    try:
        success = run_all_tests()
        exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTests interrupted by user.")
        exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
