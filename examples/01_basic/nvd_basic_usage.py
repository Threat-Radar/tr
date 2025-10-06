"""
Basic NVD API usage examples.

This example demonstrates:
- Fetching specific CVEs by ID
- Searching CVEs with various filters
- Using the local cache
- Rate limiting behavior
"""
import os
from threat_radar.core.nvd_client import NVDClient


def example1_fetch_specific_cve():
    """Example 1: Fetch a specific CVE by ID."""
    print("=" * 60)
    print("Example 1: Fetch Specific CVE (Log4Shell)")
    print("=" * 60)

    client = NVDClient()

    # Fetch the famous Log4Shell vulnerability
    cve = client.get_cve_by_id("CVE-2021-44228")

    if cve:
        print(f"\nCVE ID: {cve.cve_id}")
        print(f"Severity: {cve.severity}")
        print(f"CVSS Score: {cve.cvss_score}")
        print(f"Published: {cve.published_date}")
        print(f"Description: {cve.description[:200]}...")
        print(f"\nAffected Products: {len(cve.affected_products)}")
        print(f"References: {len(cve.references)}")
        print(f"CWE IDs: {', '.join(cve.cwe_ids)}")
    else:
        print("CVE not found")

    client.close()


def example2_search_by_keyword():
    """Example 2: Search CVEs by keyword."""
    print("\n" + "=" * 60)
    print("Example 2: Search CVEs by Keyword")
    print("=" * 60)

    client = NVDClient()

    # Search for vulnerabilities related to 'openssl'
    print("\nSearching for OpenSSL vulnerabilities...")
    cves = client.search_cves(keyword="openssl", results_per_page=5)

    print(f"\nFound {len(cves)} CVEs:")
    for cve in cves:
        print(f"\n{cve.cve_id} - {cve.severity} (CVSS: {cve.cvss_score})")
        print(f"  {cve.description[:150]}...")

    client.close()


def example3_search_by_severity():
    """Example 3: Search CVEs by severity."""
    print("\n" + "=" * 60)
    print("Example 3: Search Critical Severity CVEs")
    print("=" * 60)

    client = NVDClient()

    # Search for CRITICAL severity CVEs from last 30 days
    from datetime import datetime, timedelta

    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)

    print(f"\nSearching for CRITICAL CVEs from last 30 days...")
    cves = client.search_cves(
        cvss_severity="CRITICAL",
        last_mod_start_date=start_date,
        last_mod_end_date=end_date,
        results_per_page=10
    )

    print(f"\nFound {len(cves)} CRITICAL CVEs:")
    for cve in cves[:5]:  # Show first 5
        print(f"\n{cve.cve_id} - CVSS: {cve.cvss_score}")
        print(f"  Modified: {cve.last_modified_date[:10]}")
        print(f"  {cve.description[:120]}...")

    client.close()


def example4_recent_cves():
    """Example 4: Get recently modified CVEs."""
    print("\n" + "=" * 60)
    print("Example 4: Get Recently Modified CVEs")
    print("=" * 60)

    client = NVDClient()

    # Get CVEs modified in last 7 days
    print("\nFetching CVEs modified in last 7 days...")
    cves = client.get_recent_cves(days=7)

    print(f"\nFound {len(cves)} recently modified CVEs")

    # Group by severity
    by_severity = {}
    for cve in cves:
        severity = cve.severity or "UNKNOWN"
        by_severity[severity] = by_severity.get(severity, 0) + 1

    print("\nBreakdown by severity:")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        count = by_severity.get(severity, 0)
        if count > 0:
            print(f"  {severity}: {count}")

    client.close()


def example5_using_cache():
    """Example 5: Demonstrate caching behavior."""
    print("\n" + "=" * 60)
    print("Example 5: Caching Demonstration")
    print("=" * 60)

    client = NVDClient()

    cve_id = "CVE-2021-44228"

    # First fetch - from API (will be cached)
    print(f"\nFirst fetch of {cve_id} (from API)...")
    import time
    start = time.time()
    cve1 = client.get_cve_by_id(cve_id, use_cache=True)
    time1 = time.time() - start
    print(f"  Fetched in {time1:.3f} seconds")

    # Second fetch - from cache (should be faster)
    print(f"\nSecond fetch of {cve_id} (from cache)...")
    start = time.time()
    cve2 = client.get_cve_by_id(cve_id, use_cache=True)
    time2 = time.time() - start
    print(f"  Fetched in {time2:.3f} seconds")

    print(f"\nSpeedup: {time1/time2:.1f}x faster from cache")

    # Bypass cache
    print(f"\nThird fetch with --no-cache flag (from API)...")
    start = time.time()
    cve3 = client.get_cve_by_id(cve_id, use_cache=False)
    time3 = time.time() - start
    print(f"  Fetched in {time3:.3f} seconds")

    client.close()


def example6_with_api_key():
    """Example 6: Using NVD API key for higher rate limits."""
    print("\n" + "=" * 60)
    print("Example 6: API Key Usage")
    print("=" * 60)

    # Check if API key is set
    api_key = os.getenv("NVD_API_KEY")

    if api_key:
        print(f"\n✓ NVD API key detected")
        print("  Rate limit: 50 requests per 30 seconds")
        client = NVDClient(api_key=api_key)
    else:
        print("\n⚠ No NVD API key found")
        print("  Rate limit: 5 requests per 30 seconds")
        print("  Set NVD_API_KEY environment variable for higher limits")
        client = NVDClient()

    # Make a quick search to show it works
    print("\nTesting API access...")
    cves = client.search_cves(keyword="test", results_per_page=3)
    print(f"✓ Successfully retrieved {len(cves)} CVEs")

    client.close()


def example7_search_by_cpe():
    """Example 7: Search CVEs by CPE (Common Platform Enumeration)."""
    print("\n" + "=" * 60)
    print("Example 7: Search by CPE")
    print("=" * 60)

    client = NVDClient()

    # Search for vulnerabilities in Apache Log4j 2.14.1
    cpe = "cpe:2.3:a:apache:log4j:2.14.1"

    print(f"\nSearching for CVEs affecting: {cpe}")
    cves = client.search_cves(cpe_name=cpe, results_per_page=10)

    print(f"\nFound {len(cves)} CVEs affecting this specific version:")
    for cve in cves:
        print(f"\n{cve.cve_id} - {cve.severity} (CVSS: {cve.cvss_score})")
        print(f"  {cve.description[:150]}...")

    client.close()


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("NVD API Basic Usage Examples")
    print("=" * 60)
    print("\nNote: These examples require network access to NVD API")
    print("      Some examples may be slow due to rate limiting")
    print()

    # Run examples
    try:
        example1_fetch_specific_cve()
        example2_search_by_keyword()
        example3_search_by_severity()
        example4_recent_cves()
        example5_using_cache()
        example6_with_api_key()
        example7_search_by_cpe()

        print("\n" + "=" * 60)
        print("All examples completed successfully!")
        print("=" * 60)

    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nThis might be due to:")
        print("  - No internet connection")
        print("  - NVD API rate limits exceeded")
        print("  - NVD API temporarily unavailable")
