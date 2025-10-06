"""Debug script to understand why matching isn't working."""

from threat_radar.core.nvd_client import NVDClient
from threat_radar.core.cve_matcher import CVEMatcher, Package

# Get Shellshock CVE
print("Fetching CVE-2014-6271 (Shellshock)...")
client = NVDClient()
cve = client.get_cve_by_id("CVE-2014-6271")
client.close()

if not cve:
    print("Could not fetch CVE!")
    exit(1)

print(f"\nCVE: {cve.cve_id}")
print(f"Severity: {cve.severity}")
print(f"Description: {cve.description[:200]}...")
print(f"\nAffected Products ({len(cve.affected_products)} total):")

# Show first 10 affected products
for i, product in enumerate(cve.affected_products[:10]):
    print(f"\n  [{i+1}] CPE: {product.get('cpe23Uri', 'N/A')}")
    print(f"      Start Including: {product.get('versionStartIncluding', 'N/A')}")
    print(f"      Start Excluding: {product.get('versionStartExcluding', 'N/A')}")
    print(f"      End Including: {product.get('versionEndIncluding', 'N/A')}")
    print(f"      End Excluding: {product.get('versionEndExcluding', 'N/A')}")

# Create test packages
packages = [
    Package(name="bash", version="4.3-7ubuntu1.7", architecture="arm64"),
    Package(name="bash", version="4.4.18-2ubuntu1.3", architecture="arm64"),
    Package(name="bash", version="4.3", architecture="arm64"),
    Package(name="bash", version="4.2", architecture="arm64"),
]

print("\n" + "=" * 70)
print("TESTING MATCHER")
print("=" * 70)

matcher = CVEMatcher(min_confidence=0.5)

for pkg in packages:
    print(f"\nPackage: {pkg.name} {pkg.version}")

    # Debug CPE parsing
    bash_cpe = cve.affected_products[0]  # First one is gnu:bash
    cpe_uri = bash_cpe.get("cpe23Uri", "")
    cpe_parts = cpe_uri.split(":")
    print(f"  CPE: {cpe_uri}")
    print(f"  CPE Parts: vendor={cpe_parts[3]}, product={cpe_parts[4]}, version={cpe_parts[5]}")

    # Check name similarity
    from threat_radar.core.cve_matcher import PackageNameMatcher, VersionComparator
    name_sim = PackageNameMatcher.similarity_score(pkg.name, cpe_parts[4])
    print(f"  Name Similarity: {name_sim:.2f}")

    # Check version range
    cpe_version = cpe_parts[5]
    print(f"  CPE Version: {cpe_version}")

    if cpe_version == "*":
        print(f"  Version is wildcard, checking range...")
        in_range = VersionComparator.is_version_in_range(
            pkg.version,
            end_including=bash_cpe.get("versionEndIncluding")
        )
        print(f"  Version in range: {in_range}")

    matches = matcher.match_package(pkg, [cve])

    if matches:
        for match in matches:
            print(f"  ✓ MATCH!")
            print(f"    Confidence: {match.confidence:.2f}")
            print(f"    Reason: {match.match_reason}")
            print(f"    Version Match: {match.version_match}")
    else:
        print(f"  ✗ NO MATCH (confidence below threshold {matcher.min_confidence})")

print("\n" + "=" * 70)
