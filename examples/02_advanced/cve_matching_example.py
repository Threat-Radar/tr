"""
CVE Matching examples.

This example demonstrates:
- Version comparison and semantic versioning
- Package name fuzzy matching
- CVE matching with confidence scoring
- Bulk package vulnerability scanning
"""
from threat_radar.core.cve_matcher import (
    VersionComparator,
    PackageNameMatcher,
    CVEMatcher
)
from threat_radar.core.package_extractors import Package
from threat_radar.core.nvd_client import NVDClient, CVEItem


def example1_version_comparison():
    """Example 1: Version comparison basics."""
    print("=" * 60)
    print("Example 1: Version Comparison")
    print("=" * 60)

    test_cases = [
        ("1.2.3", "1.2.3", "equal"),
        ("1.2.3", "1.2.4", "less than"),
        ("2.0.0", "1.9.9", "greater than"),
        ("1.0.0-beta", "1.0.0", "less than (beta)"),
        ("v3.1.4", "3.1.4", "equal (with v prefix)"),
        ("2.0", "2.0.0", "equal (normalized)"),
    ]

    print("\nVersion Comparisons:")
    for v1, v2, expected in test_cases:
        result = VersionComparator.compare_versions(v1, v2)
        symbol = "=" if result == 0 else ("<" if result == -1 else ">")
        print(f"  {v1:15s} {symbol} {v2:15s}  ({expected})")


def example2_version_ranges():
    """Example 2: Version range checking."""
    print("\n" + "=" * 60)
    print("Example 2: Version Range Checking")
    print("=" * 60)

    test_version = "2.5.0"
    ranges = [
        {
            "start_including": "2.0.0",
            "end_including": "3.0.0",
            "description": "2.0.0 <= v <= 3.0.0"
        },
        {
            "start_excluding": "2.5.0",
            "end_including": "3.0.0",
            "description": "2.5.0 < v <= 3.0.0"
        },
        {
            "start_including": "1.0.0",
            "end_excluding": "2.5.0",
            "description": "1.0.0 <= v < 2.5.0"
        },
    ]

    print(f"\nChecking if version {test_version} is in range:")
    for range_spec in ranges:
        in_range = VersionComparator.is_version_in_range(
            test_version,
            start_including=range_spec.get("start_including"),
            start_excluding=range_spec.get("start_excluding"),
            end_including=range_spec.get("end_including"),
            end_excluding=range_spec.get("end_excluding")
        )
        status = "✓ IN RANGE" if in_range else "✗ OUT OF RANGE"
        print(f"  {range_spec['description']:25s} -> {status}")


def example3_package_name_matching():
    """Example 3: Package name fuzzy matching."""
    print("\n" + "=" * 60)
    print("Example 3: Package Name Fuzzy Matching")
    print("=" * 60)

    test_pairs = [
        ("openssl", "openssl"),        # Exact match
        ("libssl", "openssl"),          # Prefix removed
        ("openssl-dev", "openssl"),     # Suffix removed
        ("log4j", "log4j-core"),        # Known mapping
        ("python-requests", "requests"), # Prefix removed
        ("nginx", "nginx-full"),        # Partial match
        ("curl", "wget"),               # Different packages
    ]

    print("\nPackage Name Similarity Scores:")
    for name1, name2 in test_pairs:
        score = PackageNameMatcher.similarity_score(name1, name2)
        is_match = PackageNameMatcher.is_likely_match(name1, name2)
        match_str = "MATCH" if is_match else "NO MATCH"
        print(f"  {name1:20s} <-> {name2:20s}  Score: {score:.2f}  [{match_str}]")


def example4_simple_cve_matching():
    """Example 4: Simple CVE matching example."""
    print("\n" + "=" * 60)
    print("Example 4: Simple CVE Matching")
    print("=" * 60)

    # Create a mock package
    package = Package(
        name="openssl",
        version="1.1.1k",
        architecture="amd64"
    )

    # Create a mock CVE
    mock_cve = CVEItem(
        cve_id="CVE-2021-EXAMPLE",
        published_date="2021-03-01T00:00:00",
        last_modified_date="2021-03-01T00:00:00",
        description="Buffer overflow in OpenSSL 1.1.1k allows remote code execution",
        severity="HIGH",
        cvss_score=8.1,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        affected_products=[{
            "cpe23Uri": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
            "versionStartIncluding": None,
            "versionStartExcluding": None,
            "versionEndIncluding": None,
            "versionEndExcluding": None,
        }],
        references=["https://www.openssl.org/news/secadv/20210301.txt"],
        cwe_ids=["CWE-119"]
    )

    # Match package against CVE
    matcher = CVEMatcher(min_confidence=0.5)
    matches = matcher.match_package(package, [mock_cve])

    print(f"\nPackage: {package.name} {package.version}")
    print(f"Checking against: {mock_cve.cve_id}")
    print(f"\nMatches found: {len(matches)}")

    if matches:
        for match in matches:
            print(f"\n  CVE: {match.cve.cve_id}")
            print(f"  Confidence: {match.confidence:.0%}")
            print(f"  Reason: {match.match_reason}")
            print(f"  Version Match: {'Yes' if match.version_match else 'No'}")
            print(f"  CPE: {match.cpe_uri}")


def example5_bulk_matching():
    """Example 5: Bulk package matching."""
    print("\n" + "=" * 60)
    print("Example 5: Bulk Package Matching")
    print("=" * 60)

    # Create multiple packages
    packages = [
        Package("openssl", "1.1.1k", "amd64"),
        Package("curl", "7.68.0", "amd64"),
        Package("nginx", "1.18.0", "amd64"),
        Package("python3", "3.8.5", "amd64"),
    ]

    # Create mock CVEs
    mock_cves = [
        CVEItem(
            cve_id="CVE-2021-OPENSSL",
            published_date="2021-01-01T00:00:00",
            last_modified_date="2021-01-01T00:00:00",
            description="OpenSSL vulnerability",
            severity="HIGH",
            cvss_score=7.5,
            affected_products=[{
                "cpe23Uri": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
            }]
        ),
        CVEItem(
            cve_id="CVE-2021-NGINX",
            published_date="2021-01-01T00:00:00",
            last_modified_date="2021-01-01T00:00:00",
            description="Nginx vulnerability",
            severity="MEDIUM",
            cvss_score=5.3,
            affected_products=[{
                "cpe23Uri": "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*",
            }]
        ),
    ]

    # Bulk match
    matcher = CVEMatcher(min_confidence=0.6)
    results = matcher.bulk_match_packages(packages, mock_cves)

    print(f"\nScanned {len(packages)} packages against {len(mock_cves)} CVEs")
    print(f"Vulnerable packages: {len(results)}")

    for package_name, matches in results.items():
        print(f"\n📦 {package_name}:")
        for match in matches:
            print(f"  ⚠ {match.cve.cve_id} - Confidence: {match.confidence:.0%}")
            print(f"     {match.match_reason}")


def example6_confidence_thresholds():
    """Example 6: Effect of confidence thresholds."""
    print("\n" + "=" * 60)
    print("Example 6: Confidence Thresholds")
    print("=" * 60)

    # Package with slight name variation
    package = Package("libssl", "1.1.1", "amd64")

    # CVE for openssl (similar but not exact)
    cve = CVEItem(
        cve_id="CVE-2021-TEST",
        published_date="2021-01-01T00:00:00",
        last_modified_date="2021-01-01T00:00:00",
        description="OpenSSL vulnerability",
        severity="HIGH",
        cvss_score=7.5,
        affected_products=[{
            "cpe23Uri": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
            "versionStartIncluding": "1.1.0",
            "versionEndIncluding": "1.1.1k",
        }]
    )

    print(f"\nPackage: {package.name} {package.version}")
    print(f"CVE: {cve.cve_id} (affects openssl)")

    # Try different thresholds
    thresholds = [0.5, 0.6, 0.7, 0.8, 0.9]

    print("\nMatching with different confidence thresholds:")
    for threshold in thresholds:
        matcher = CVEMatcher(min_confidence=threshold)
        matches = matcher.match_package(package, [cve])

        if matches:
            print(f"  {threshold:.1f}: ✓ MATCHED (confidence: {matches[0].confidence:.2f})")
        else:
            print(f"  {threshold:.1f}: ✗ No match (below threshold)")


def example7_real_world_scenario():
    """Example 7: Real-world vulnerability scanning."""
    print("\n" + "=" * 60)
    print("Example 7: Real-World Vulnerability Scan")
    print("=" * 60)

    print("\nSimulating vulnerability scan for a Docker container...")

    # Simulated package list from a container
    packages = [
        Package("openssl", "1.1.1d", "amd64"),
        Package("curl", "7.64.0", "amd64"),
        Package("libssl1.1", "1.1.1d", "amd64"),
        Package("zlib1g", "1.2.11", "amd64"),
        Package("bash", "5.0", "amd64"),
    ]

    print(f"\nFound {len(packages)} packages in container")

    # Fetch real CVEs from NVD
    print("\nFetching recent CVEs from NVD...")
    client = NVDClient()

    # Search for recent CVEs
    cves = client.search_cves(
        keyword="openssl",
        results_per_page=10
    )
    print(f"Retrieved {len(cves)} CVEs from NVD")

    # Match packages against CVEs
    print("\nMatching packages against CVEs...")
    matcher = CVEMatcher(min_confidence=0.7)
    results = matcher.bulk_match_packages(packages, cves)

    # Display results
    if results:
        print(f"\n⚠ Found vulnerabilities in {len(results)} packages:\n")
        for pkg_name, matches in results.items():
            print(f"📦 {pkg_name}:")
            for match in matches[:3]:  # Show top 3
                print(f"  • {match.cve.cve_id} - {match.cve.severity} "
                      f"(CVSS: {match.cve.cvss_score}, Confidence: {match.confidence:.0%})")
                print(f"    {match.match_reason}")
    else:
        print("\n✓ No vulnerabilities found")

    client.close()


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("CVE Matching Examples")
    print("=" * 60)
    print()

    try:
        example1_version_comparison()
        example2_version_ranges()
        example3_package_name_matching()
        example4_simple_cve_matching()
        example5_bulk_matching()
        example6_confidence_thresholds()

        print("\n\nNote: Skipping example 7 (real-world scenario)")
        print("      Uncomment to run with live NVD data")
        # example7_real_world_scenario()

        print("\n" + "=" * 60)
        print("All examples completed successfully!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
