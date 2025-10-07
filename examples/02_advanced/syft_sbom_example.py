"""Example usage of Syft SBOM integration."""
import json
from pathlib import Path
from threat_radar.core.syft_integration import SyftClient, SBOMFormat
from threat_radar.utils.sbom_utils import (
    save_sbom,
    load_sbom,
    compare_sboms,
    get_package_statistics,
    extract_licenses,
    search_packages
)
from threat_radar.utils.sbom_storage import (
    get_docker_sbom_path,
    get_local_sbom_path,
    get_comparison_path,
    ensure_storage_directories
)


def example_scan_current_project():
    """Example: Generate SBOM for current project."""
    print("=" * 60)
    print("Example 1: Scan Current Project")
    print("=" * 60)

    # Ensure storage directories exist
    ensure_storage_directories()

    client = SyftClient()

    # Scan current directory
    print("\nScanning current project...")
    sbom = client.scan_directory(".", output_format=SBOMFormat.CYCLONEDX_JSON)

    # Get package count
    package_count = client.get_package_count(sbom)
    print(f"\nFound {package_count} packages")

    # Show package types
    stats = get_package_statistics(sbom)
    print("\nPackages by type:")
    for pkg_type, count in sorted(stats.items(), key=lambda x: x[1], reverse=True):
        print(f"  {pkg_type}: {count}")

    # Save SBOM to organized storage
    output_file = get_local_sbom_path("threat-radar", format="json")
    save_sbom(sbom, output_file)
    print(f"\nSBOM saved to {output_file}")


def example_scan_docker_image():
    """Example: Generate SBOM for Docker image."""
    print("\n" + "=" * 60)
    print("Example 2: Scan Docker Image")
    print("=" * 60)

    client = SyftClient()

    # Scan Alpine Linux image
    image = "alpine:3.18"
    print(f"\nScanning Docker image: {image}...")

    sbom = client.scan_docker_image(
        image,
        output_format=SBOMFormat.CYCLONEDX_JSON,
        scope="squashed"
    )

    packages = client.parse_syft_json(
        client.scan_docker_image(image, output_format=SBOMFormat.SYFT_JSON)
    )

    print(f"\nFound {len(packages)} packages")
    print("\nFirst 10 packages:")
    for pkg in packages[:10]:
        print(f"  - {pkg.name} {pkg.version} ({pkg.type})")


def example_compare_docker_images():
    """Example: Compare packages between two Docker images."""
    print("\n" + "=" * 60)
    print("Example 3: Compare Docker Images")
    print("=" * 60)

    client = SyftClient()

    # Scan two different Alpine versions
    image1 = "alpine:3.17"
    image2 = "alpine:3.18"

    print(f"\nScanning {image1}...")
    sbom1 = client.scan_docker_image(image1, output_format=SBOMFormat.CYCLONEDX_JSON)

    # Save individual Docker SBOMs
    sbom1_path = get_docker_sbom_path("alpine", "3.17", format="json")
    save_sbom(sbom1, sbom1_path)

    print(f"Scanning {image2}...")
    sbom2 = client.scan_docker_image(image2, output_format=SBOMFormat.CYCLONEDX_JSON)

    sbom2_path = get_docker_sbom_path("alpine", "3.18", format="json")
    save_sbom(sbom2, sbom2_path)

    # Compare
    diff = compare_sboms(sbom1, sbom2)

    print(f"\n{'=' * 60}")
    print("Comparison Results")
    print("=" * 60)
    print(f"Common packages: {len(diff['common'])}")
    print(f"Added in {image2}: {len(diff['added'])}")
    print(f"Removed from {image1}: {len(diff['removed'])}")

    if diff['added']:
        print(f"\nNew packages in {image2}:")
        for pkg in sorted(list(diff['added']))[:10]:
            print(f"  + {pkg}")

    if diff['removed']:
        print(f"\nRemoved packages:")
        for pkg in sorted(list(diff['removed']))[:10]:
            print(f"  - {pkg}")

    # Save comparison result
    comparison_path = get_comparison_path("alpine-3.17", "alpine-3.18", format="json")
    comparison_data = {
        "sbom1": str(sbom1_path),
        "sbom2": str(sbom2_path),
        "common_count": len(diff['common']),
        "added_count": len(diff['added']),
        "removed_count": len(diff['removed']),
        "added": sorted(list(diff['added'])),
        "removed": sorted(list(diff['removed']))
    }
    save_sbom(comparison_data, comparison_path)
    print(f"\nComparison saved to {comparison_path}")


def example_scan_with_multiple_formats():
    """Example: Generate SBOM in multiple formats."""
    print("\n" + "=" * 60)
    print("Example 4: Multiple SBOM Formats")
    print("=" * 60)

    client = SyftClient()
    target = "alpine:3.18"

    formats = [
        (SBOMFormat.CYCLONEDX_JSON, "json"),
        (SBOMFormat.SPDX_JSON, "spdx.json"),
        (SBOMFormat.SYFT_JSON, "syft.json"),
    ]

    print(f"\nGenerating SBOMs for {target}...\n")

    for sbom_format, file_ext in formats:
        print(f"Generating {sbom_format.value}...")
        sbom = client.scan_docker_image(target, output_format=sbom_format)

        if isinstance(sbom, dict):
            output_path = get_docker_sbom_path("alpine", "3.18", format=file_ext)
            save_sbom(sbom, output_path)
            print(f"  ✓ Saved to {output_path}")


def example_license_analysis():
    """Example: Analyze licenses in SBOM."""
    print("\n" + "=" * 60)
    print("Example 5: License Analysis")
    print("=" * 60)

    client = SyftClient()

    # Scan Python image (has more packages with licenses)
    image = "python:3.11-slim"
    print(f"\nScanning {image} for license information...")

    sbom = client.scan_docker_image(image, output_format=SBOMFormat.SYFT_JSON)
    packages = client.parse_syft_json(sbom)

    # Count packages with licenses
    packages_with_licenses = [p for p in packages if p.licenses]
    print(f"\nTotal packages: {len(packages)}")
    print(f"Packages with license info: {len(packages_with_licenses)}")

    # Show license distribution
    license_counts = {}
    for pkg in packages_with_licenses:
        for lic in pkg.licenses:
            # Handle both string and dict license formats
            license_name = lic if isinstance(lic, str) else lic.get('value', str(lic))
            license_counts[license_name] = license_counts.get(license_name, 0) + 1

    print("\nTop 10 licenses:")
    sorted_licenses = sorted(license_counts.items(), key=lambda x: x[1], reverse=True)
    for lic, count in sorted_licenses[:10]:
        print(f"  {lic}: {count} packages")


def example_search_packages():
    """Example: Search for specific packages in SBOM."""
    print("\n" + "=" * 60)
    print("Example 6: Package Search")
    print("=" * 60)

    client = SyftClient()

    # Generate SBOM for current project
    print("\nScanning current project...")
    sbom = client.scan_directory(".", output_format=SBOMFormat.CYCLONEDX_JSON)

    # Search for packages
    search_terms = ["python", "typer", "docker"]

    for term in search_terms:
        results = search_packages(sbom, term)
        if results:
            print(f"\nPackages matching '{term}':")
            for pkg in results[:5]:
                print(f"  - {pkg.get('name')} {pkg.get('version')}")


def example_supported_ecosystems():
    """Example: Show supported package ecosystems."""
    print("\n" + "=" * 60)
    print("Example 7: Supported Ecosystems")
    print("=" * 60)

    client = SyftClient()
    ecosystems = client.get_supported_ecosystems()

    print("\nSyft supports the following package ecosystems:")
    for ecosystem in ecosystems:
        print(f"  • {ecosystem}")

    print("\nYou can scan projects in any of these languages!")


def example_package_locations():
    """Example: Show where packages are located in the filesystem."""
    print("\n" + "=" * 60)
    print("Example 8: Package Locations")
    print("=" * 60)

    client = SyftClient()

    image = "python:3.11-slim"
    print(f"\nScanning {image}...")

    sbom = client.scan_docker_image(image, output_format=SBOMFormat.SYFT_JSON)
    packages = client.parse_syft_json(sbom)

    print("\nSample packages with locations:")
    count = 0
    for pkg in packages:
        if pkg.locations and count < 10:
            print(f"\n{pkg.name} {pkg.version}")
            print(f"  Type: {pkg.type}")
            print(f"  Locations:")
            for loc in pkg.locations[:3]:  # Show first 3 locations
                print(f"    - {loc}")
            count += 1


def example_scan_requirements_file():
    """Example: Scan a single requirements.txt file."""
    print("\n" + "=" * 60)
    print("Example 9: Scan Requirements File")
    print("=" * 60)

    # Create a sample requirements.txt
    sample_requirements = Path("/tmp/requirements.txt")
    sample_requirements.write_text("""
django==4.2.0
requests==2.31.0
pytest==7.4.0
black==23.3.0
""".strip())

    print(f"\nScanning {sample_requirements}...")

    client = SyftClient()
    sbom = client.scan_file(sample_requirements, output_format=SBOMFormat.SYFT_JSON)

    packages = client.parse_syft_json(sbom)
    print(f"\nFound {len(packages)} packages:")
    for pkg in packages:
        print(f"  - {pkg.name} {pkg.version}")


if __name__ == "__main__":
    """Run all examples."""
    try:
        print("\n" + "=" * 60)
        print("Syft SBOM Integration Examples")
        print("=" * 60)

        # Run examples
        example_scan_current_project()
        example_scan_docker_image()
        example_compare_docker_images()
        example_scan_with_multiple_formats()
        example_license_analysis()
        example_search_packages()
        example_supported_ecosystems()
        example_package_locations()
        example_scan_requirements_file()

        print("\n" + "=" * 60)
        print("All examples completed!")
        print("=" * 60)

    except RuntimeError as e:
        print(f"\nError: {e}")
        print("\nMake sure:")
        print("  1. Syft is installed (https://github.com/anchore/syft#installation)")
        print("  2. Docker is running (for Docker image examples)")
        print("  3. You have network connectivity")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
