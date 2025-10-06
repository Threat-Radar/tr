"""
CVE Database usage examples.

This example demonstrates:
- Building a local CVE database
- Incremental updates
- Searching the local database
- Database statistics
"""
from threat_radar.core.cve_database import CVEDatabase
from threat_radar.core.nvd_client import NVDClient


def example1_initialize_database():
    """Example 1: Initialize and populate local CVE database."""
    print("=" * 60)
    print("Example 1: Initialize CVE Database")
    print("=" * 60)

    # Initialize database (creates if doesn't exist)
    db = CVEDatabase()

    print(f"\nDatabase location: {db.db_path}")

    # Get initial stats
    stats = db.get_stats()
    print(f"\nInitial database state:")
    print(f"  Total CVEs: {stats['total_cves']}")
    print(f"  Last update: {stats.get('last_update', 'Never')}")

    db.close()


def example2_update_database():
    """Example 2: Update database with recent CVEs."""
    print("\n" + "=" * 60)
    print("Example 2: Update Database with Recent CVEs")
    print("=" * 60)

    db = CVEDatabase()

    # Update with CVEs from last 7 days
    print("\nUpdating database with CVEs from last 7 days...")
    print("(This may take a few minutes due to rate limiting)")

    count = db.update_from_nvd(days=7, force=False)

    print(f"\n✓ Updated {count} CVEs")

    # Show updated stats
    stats = db.get_stats()
    print(f"\nDatabase now contains:")
    print(f"  Total CVEs: {stats['total_cves']}")
    print(f"  Last update: {stats.get('last_update')}")

    db.close()


def example3_search_local_database():
    """Example 3: Search the local database."""
    print("\n" + "=" * 60)
    print("Example 3: Search Local Database")
    print("=" * 60)

    db = CVEDatabase()

    # Search 1: Find CRITICAL severity CVEs
    print("\nSearch 1: CRITICAL severity CVEs")
    cves = db.search_cves(severity="CRITICAL", limit=5)
    print(f"Found {len(cves)} CRITICAL CVEs:")
    for cve in cves:
        print(f"  {cve.cve_id} - CVSS: {cve.cvss_score}")

    # Search 2: Find CVEs with CVSS >= 9.0
    print("\nSearch 2: CVEs with CVSS score >= 9.0")
    cves = db.search_cves(min_cvss_score=9.0, limit=5)
    print(f"Found {len(cves)} high-score CVEs:")
    for cve in cves:
        print(f"  {cve.cve_id} - CVSS: {cve.cvss_score} ({cve.severity})")

    # Search 3: Keyword search
    print("\nSearch 3: Keyword search for 'remote code execution'")
    cves = db.search_cves(keyword="remote code execution", limit=5)
    print(f"Found {len(cves)} CVEs:")
    for cve in cves:
        print(f"  {cve.cve_id} - {cve.description[:80]}...")

    db.close()


def example4_get_specific_cve():
    """Example 4: Retrieve specific CVE from database."""
    print("\n" + "=" * 60)
    print("Example 4: Retrieve Specific CVE")
    print("=" * 60)

    db = CVEDatabase()

    # Try to get a specific CVE (if it exists in local DB)
    cve_id = "CVE-2021-44228"  # Log4Shell

    print(f"\nLooking up {cve_id} in local database...")
    cve = db.get_cve(cve_id)

    if cve:
        print(f"\n✓ Found in local database:")
        print(f"  CVE ID: {cve.cve_id}")
        print(f"  Severity: {cve.severity}")
        print(f"  CVSS Score: {cve.cvss_score}")
        print(f"  Published: {cve.published_date}")
        print(f"  Description: {cve.description[:150]}...")
    else:
        print(f"\n⚠ {cve_id} not found in local database")
        print("  Run 'threat-radar cve update' to populate the database")

    db.close()


def example5_database_statistics():
    """Example 5: Analyze database statistics."""
    print("\n" + "=" * 60)
    print("Example 5: Database Statistics")
    print("=" * 60)

    db = CVEDatabase()

    stats = db.get_stats()

    print(f"\nDatabase Statistics:")
    print(f"  Location: {db.db_path}")
    print(f"  Total CVEs: {stats['total_cves']:,}")
    print(f"  Last Update: {stats.get('last_update', 'Never')}")

    # Date range
    if stats.get('date_range'):
        print(f"\nDate Range:")
        print(f"  Earliest: {stats['date_range']['earliest']}")
        print(f"  Latest: {stats['date_range']['latest']}")

    # Severity breakdown
    if stats.get('by_severity'):
        print(f"\nSeverity Distribution:")
        total = stats['total_cves']
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = stats['by_severity'].get(severity, 0)
            if count > 0:
                percentage = (count / total * 100) if total > 0 else 0
                print(f"  {severity:8s}: {count:5,} ({percentage:5.1f}%)")

    db.close()


def example6_incremental_updates():
    """Example 6: Demonstrate incremental update behavior."""
    print("\n" + "=" * 60)
    print("Example 6: Incremental Updates")
    print("=" * 60)

    db = CVEDatabase()

    print("\nAttempting first update...")
    count1 = db.update_from_nvd(days=7, force=False)
    print(f"  Added/updated: {count1} CVEs")

    print("\nAttempting immediate second update (should skip)...")
    count2 = db.update_from_nvd(days=7, force=False)
    print(f"  Added/updated: {count2} CVEs")
    print("  (Should be 0 - updates are throttled to prevent abuse)")

    print("\nForcing update with force=True...")
    count3 = db.update_from_nvd(days=7, force=True)
    print(f"  Added/updated: {count3} CVEs")

    db.close()


def example7_store_custom_cve():
    """Example 7: Manually store CVE data."""
    print("\n" + "=" * 60)
    print("Example 7: Manually Store CVE")
    print("=" * 60)

    # Get a CVE from NVD
    client = NVDClient()
    cve = client.get_cve_by_id("CVE-2021-44228")
    client.close()

    if not cve:
        print("\nCould not fetch CVE from NVD")
        return

    # Store it in the database
    db = CVEDatabase()

    print(f"\nStoring {cve.cve_id} in database...")
    success = db.store_cve(cve)

    if success:
        print(f"✓ Successfully stored {cve.cve_id}")

        # Verify it was stored
        retrieved = db.get_cve(cve.cve_id)
        if retrieved:
            print(f"✓ Verified: {retrieved.cve_id} is in database")
            print(f"  Severity: {retrieved.severity}")
            print(f"  CVSS: {retrieved.cvss_score}")
    else:
        print(f"❌ Failed to store {cve.cve_id}")

    db.close()


def example8_combined_search():
    """Example 8: Complex search with multiple filters."""
    print("\n" + "=" * 60)
    print("Example 8: Complex Multi-Filter Search")
    print("=" * 60)

    db = CVEDatabase()

    # Search for high-severity CVEs with specific keyword
    print("\nSearching for:")
    print("  - Severity: HIGH or CRITICAL")
    print("  - CVSS score >= 8.0")
    print("  - Keyword: 'overflow'")

    # First get HIGH severity
    high_cves = db.search_cves(
        severity="HIGH",
        min_cvss_score=8.0,
        keyword="overflow",
        limit=5
    )

    # Then get CRITICAL severity
    critical_cves = db.search_cves(
        severity="CRITICAL",
        min_cvss_score=8.0,
        keyword="overflow",
        limit=5
    )

    all_cves = high_cves + critical_cves
    print(f"\nFound {len(all_cves)} matching CVEs:")

    for cve in all_cves[:10]:  # Show up to 10
        print(f"\n{cve.cve_id} - {cve.severity} (CVSS: {cve.cvss_score})")
        print(f"  {cve.description[:120]}...")

    db.close()


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("CVE Database Usage Examples")
    print("=" * 60)
    print("\nThese examples demonstrate local CVE database operations")
    print()

    try:
        example1_initialize_database()
        example2_update_database()
        example3_search_local_database()
        example4_get_specific_cve()
        example5_database_statistics()
        example6_incremental_updates()
        example7_store_custom_cve()
        example8_combined_search()

        print("\n" + "=" * 60)
        print("All examples completed successfully!")
        print("=" * 60)
        print("\nLocal database created at: ~/.threat_radar/cve.db")
        print("Cache directory: ~/.threat_radar/cache/")

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
