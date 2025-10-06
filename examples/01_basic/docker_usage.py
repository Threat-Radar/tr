"""Example usage of Docker integration features."""
import json
from threat_radar.core.container_analyzer import ContainerAnalyzer


def example_basic_analysis():
    """Example: Basic container analysis."""
    print("=" * 60)
    print("Example 1: Basic Container Analysis")
    print("=" * 60)

    analyzer = ContainerAnalyzer()

    # Import (pull) and analyze a small Alpine image
    print("\nImporting alpine:3.18...")
    analysis = analyzer.import_container("alpine", tag="3.18")

    print(f"\nImage: {analysis.image_name}")
    print(f"Distribution: {analysis.distro} {analysis.distro_version or ''}")
    print(f"Architecture: {analysis.architecture}")
    print(f"Total packages: {len(analysis.packages)}")

    # Show first 5 packages
    print("\nFirst 5 packages:")
    for pkg in analysis.packages[:5]:
        print(f"  - {pkg.name} ({pkg.version})")

    analyzer.close()


def example_import_and_analyze():
    """Example: Import (pull) and analyze an image."""
    print("\n" + "=" * 60)
    print("Example 2: Import and Analyze Image")
    print("=" * 60)

    analyzer = ContainerAnalyzer()

    # Import Ubuntu image (will pull if not present)
    print("\nImporting ubuntu:22.04...")
    analysis = analyzer.import_container("ubuntu", tag="22.04")

    print(f"\nImage ID: {analysis.image_id[:12]}")
    print(f"Distribution: {analysis.distro} {analysis.distro_version}")
    print(f"Size: {analysis.size / (1024**2):.1f} MB")
    print(f"Total packages: {len(analysis.packages)}")

    analyzer.close()


def example_package_search():
    """Example: Search for specific packages."""
    print("\n" + "=" * 60)
    print("Example 3: Search for Specific Packages")
    print("=" * 60)

    analyzer = ContainerAnalyzer()

    print("\nAnalyzing alpine:3.18 (using locally cached image)...")
    analysis = analyzer.analyze_container("alpine:3.18")

    # Search for packages containing 'ssl'
    search_term = "ssl"
    matching_packages = [
        pkg for pkg in analysis.packages
        if search_term in pkg.name.lower()
    ]

    print(f"\nPackages containing '{search_term}':")
    for pkg in matching_packages:
        print(f"  - {pkg.name} {pkg.version}")

    analyzer.close()


def example_compare_images():
    """Example: Compare packages between two images."""
    print("\n" + "=" * 60)
    print("Example 4: Compare Packages Between Images")
    print("=" * 60)

    analyzer = ContainerAnalyzer()

    # Import and analyze two Alpine versions
    print("\nImporting alpine:3.18...")
    analysis_new = analyzer.import_container("alpine", tag="3.18")

    print("\nImporting alpine:3.17...")
    analysis_old = analyzer.import_container("alpine", tag="3.17")

    # Get package names as sets
    packages_new = {pkg.name for pkg in analysis_new.packages}
    packages_old = {pkg.name for pkg in analysis_old.packages}

    # Find differences
    added = packages_new - packages_old
    removed = packages_old - packages_new
    common = packages_new & packages_old

    print(f"\nCommon packages: {len(common)}")
    print(f"Added in 3.18: {len(added)}")
    print(f"Removed from 3.17: {len(removed)}")

    if added:
        print("\nNew packages in 3.18:")
        for pkg_name in sorted(list(added)[:5]):
            print(f"  + {pkg_name}")

    if removed:
        print("\nRemoved packages:")
        for pkg_name in sorted(list(removed)[:5]):
            print(f"  - {pkg_name}")

    analyzer.close()


def example_export_to_json():
    """Example: Export analysis results to JSON."""
    print("\n" + "=" * 60)
    print("Example 5: Export Analysis to JSON")
    print("=" * 60)

    analyzer = ContainerAnalyzer()

    print("\nAnalyzing alpine:3.18 (using locally cached image)...")
    analysis = analyzer.analyze_container("alpine:3.18")

    # Convert to dictionary
    from dataclasses import asdict
    result = asdict(analysis)

    # Save to file
    output_file = "/tmp/alpine_analysis.json"
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)

    print(f"\nAnalysis saved to: {output_file}")
    print(f"Total size: {len(json.dumps(result))} bytes")

    # Show sample of JSON structure
    print("\nSample JSON structure:")
    print(json.dumps({
        "image_name": result["image_name"],
        "distro": result["distro"],
        "package_count": len(result["packages"]),
        "sample_package": result["packages"][0] if result["packages"] else None
    }, indent=2))

    analyzer.close()


def example_list_images():
    """Example: List all available Docker images."""
    print("\n" + "=" * 60)
    print("Example 6: List Available Images")
    print("=" * 60)

    analyzer = ContainerAnalyzer()

    print("\nListing all Docker images...")
    images = analyzer.list_analyzed_images()

    print(f"\nFound {len(images)} images:\n")
    for img in images[:10]:  # Show first 10
        tags = ', '.join(img['tags']) if img['tags'] else '<none>'
        size_mb = img['size'] / (1024**2) if img['size'] else 0
        print(f"  {img['id'][:12]} | {tags} | {size_mb:.1f} MB")

    if len(images) > 10:
        print(f"\n  ... and {len(images) - 10} more images")

    analyzer.close()


def example_analyze_multiple_distros():
    """Example: Analyze different Linux distributions."""
    print("\n" + "=" * 60)
    print("Example 7: Analyze Multiple Distributions")
    print("=" * 60)

    analyzer = ContainerAnalyzer()

    images = [
        ("alpine", "3.18", "Alpine Linux"),
        ("debian", "12", "Debian"),
        ("ubuntu", "22.04", "Ubuntu"),
    ]

    results = []

    for image_name, tag, distro_name in images:
        try:
            print(f"\nImporting {distro_name} ({image_name}:{tag})...")
            analysis = analyzer.import_container(image_name, tag=tag)

            results.append({
                'name': distro_name,
                'image': f"{image_name}:{tag}",
                'packages': len(analysis.packages),
                'size': analysis.size / (1024**2) if analysis.size else 0
            })
        except Exception as err:
            print(f"  Error: {err}")

    # Summary table
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"{'Distribution':<20} {'Packages':<12} {'Size (MB)':<12}")
    print("-" * 60)

    for result in results:
        print(f"{result['name']:<20} {result['packages']:<12} {result['size']:<12.1f}")

    analyzer.close()


def example_package_statistics():
    """Example: Generate package statistics."""
    print("\n" + "=" * 60)
    print("Example 8: Package Statistics")
    print("=" * 60)

    analyzer = ContainerAnalyzer()

    print("\nAnalyzing ubuntu:22.04 (using locally cached image)...")
    analysis = analyzer.analyze_container("ubuntu:22.04")

    # Count packages by architecture
    arch_counts = {}
    for pkg in analysis.packages:
        arch = pkg.architecture or 'unknown'
        arch_counts[arch] = arch_counts.get(arch, 0) + 1

    print(f"\nTotal packages: {len(analysis.packages)}")
    print("\nPackages by architecture:")
    for arch, count in sorted(arch_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {arch}: {count}")

    # Find longest package name
    if analysis.packages:
        longest = max(analysis.packages, key=lambda p: len(p.name))
        print(f"\nLongest package name: {longest.name} ({len(longest.name)} chars)")

    analyzer.close()


if __name__ == "__main__":
    """Run all examples."""
    try:
        # Run examples
        example_basic_analysis()
        example_import_and_analyze()
        example_package_search()
        example_compare_images()
        example_export_to_json()
        example_list_images()
        example_analyze_multiple_distros()
        example_package_statistics()

        print("\n" + "=" * 60)
        print("All examples completed!")
        print("=" * 60)

    except Exception as e:
        print(f"\nError running examples: {e}")
        print("\nMake sure Docker is running and you have network connectivity.")
        print("Some images may need to be pulled first.")
