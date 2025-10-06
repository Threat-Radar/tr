"""Advanced Docker integration examples."""
import json
from pathlib import Path
from typing import List, Dict, Set
from collections import defaultdict
from threat_radar.core.container_analyzer import ContainerAnalyzer, ContainerAnalysis


class DockerSecurityAnalyzer:
    """Advanced security analysis for Docker images."""

    def __init__(self):
        self.analyzer = ContainerAnalyzer()

    def find_vulnerable_packages(self, image_name: str, known_vulnerable: List[str]) -> List[Dict]:
        """
        Find packages matching known vulnerable package list.

        Args:
            image_name: Docker image to analyze
            known_vulnerable: List of vulnerable package names

        Returns:
            List of matching packages with details
        """
        analysis = self.analyzer.analyze_container(image_name)

        vulnerable = []
        for pkg in analysis.packages:
            if pkg.name in known_vulnerable:
                vulnerable.append({
                    'name': pkg.name,
                    'version': pkg.version,
                    'architecture': pkg.architecture
                })

        return vulnerable

    def generate_sbom(self, image_name: str) -> Dict:
        """
        Generate a Software Bill of Materials (SBOM) for an image.

        Args:
            image_name: Docker image to analyze

        Returns:
            SBOM dictionary in basic format
        """
        analysis = self.analyzer.analyze_container(image_name)

        sbom = {
            'image': {
                'name': analysis.image_name,
                'id': analysis.image_id,
                'distro': analysis.distro,
                'version': analysis.distro_version,
            },
            'packages': [
                {
                    'name': pkg.name,
                    'version': pkg.version,
                    'architecture': pkg.architecture,
                } for pkg in analysis.packages
            ],
            'metadata': {
                'total_packages': len(analysis.packages),
                'image_size': analysis.size,
                'created': analysis.created,
            }
        }

        return sbom

    def compare_images(self, image1: str, image2: str) -> Dict:
        """
        Compare packages between two images.

        Args:
            image1: First image name
            image2: Second image name

        Returns:
            Comparison results
        """
        analysis1 = self.analyzer.analyze_container(image1)
        analysis2 = self.analyzer.analyze_container(image2)

        # Create package name -> version mappings
        packages1 = {pkg.name: pkg.version for pkg in analysis1.packages}
        packages2 = {pkg.name: pkg.version for pkg in analysis2.packages}

        added = set(packages2.keys()) - set(packages1.keys())
        removed = set(packages1.keys()) - set(packages2.keys())
        common = set(packages1.keys()) & set(packages2.keys())

        # Find version changes in common packages
        updated = []
        for pkg_name in common:
            if packages1[pkg_name] != packages2[pkg_name]:
                updated.append({
                    'name': pkg_name,
                    'old_version': packages1[pkg_name],
                    'new_version': packages2[pkg_name]
                })

        return {
            'image1': image1,
            'image2': image2,
            'added': sorted(list(added)),
            'removed': sorted(list(removed)),
            'updated': updated,
            'unchanged': len(common) - len(updated),
            'total_changes': len(added) + len(removed) + len(updated)
        }

    def analyze_package_origins(self, image_name: str) -> Dict:
        """
        Analyze where packages might come from (based on naming patterns).

        Args:
            image_name: Docker image to analyze

        Returns:
            Statistics about package origins
        """
        analysis = self.analyzer.analyze_container(image_name)

        # Categorize by common prefixes/patterns
        categories = defaultdict(list)

        for pkg in analysis.packages:
            name = pkg.name.lower()

            # Categorize by common patterns
            if name.startswith('python') or name.startswith('py-'):
                categories['python'].append(pkg.name)
            elif name.startswith('lib'):
                categories['libraries'].append(pkg.name)
            elif name.startswith('perl'):
                categories['perl'].append(pkg.name)
            elif 'ssl' in name or 'tls' in name or 'crypto' in name:
                categories['security'].append(pkg.name)
            elif 'dev' in name or 'devel' in name:
                categories['development'].append(pkg.name)
            else:
                categories['other'].append(pkg.name)

        return {
            'categories': {k: len(v) for k, v in categories.items()},
            'details': dict(categories)
        }

    def close(self):
        """Close analyzer."""
        self.analyzer.close()


def example_vulnerability_check():
    """Example: Check for known vulnerable packages."""
    print("=" * 60)
    print("Example: Vulnerability Check")
    print("=" * 60)

    analyzer = DockerSecurityAnalyzer()

    # Simulated list of vulnerable packages
    vulnerable_packages = [
        'openssl',  # Example: might be vulnerable version
        'curl',
        'busybox',
        'wget'
    ]

    image = "alpine:3.18"
    print(f"\nChecking {image} for vulnerable packages...")

    found = analyzer.find_vulnerable_packages(image, vulnerable_packages)

    if found:
        print(f"\nFound {len(found)} potentially vulnerable packages:")
        for pkg in found:
            print(f"  - {pkg['name']} {pkg['version']}")
    else:
        print("\nNo matches found in vulnerable package list")

    analyzer.close()


def example_sbom_generation():
    """Example: Generate SBOM for an image."""
    print("\n" + "=" * 60)
    print("Example: SBOM Generation")
    print("=" * 60)

    analyzer = DockerSecurityAnalyzer()

    image = "alpine:3.18"
    print(f"\nGenerating SBOM for {image}...")

    sbom = analyzer.generate_sbom(image)

    # Save SBOM
    output_file = "/tmp/alpine_sbom.json"
    with open(output_file, 'w') as f:
        json.dump(sbom, f, indent=2)

    print(f"\nSBOM generated and saved to {output_file}")
    print(f"Total packages: {sbom['metadata']['total_packages']}")
    print(f"Image size: {sbom['metadata']['image_size'] / (1024**2):.1f} MB")

    # Show sample packages
    print("\nSample packages:")
    for pkg in sbom['packages'][:5]:
        print(f"  - {pkg['name']} {pkg['version']}")

    analyzer.close()


def example_image_comparison():
    """Example: Compare two images."""
    print("\n" + "=" * 60)
    print("Example: Image Comparison")
    print("=" * 60)

    analyzer = DockerSecurityAnalyzer()

    image1 = "alpine:3.17"
    image2 = "alpine:3.18"

    print(f"\nComparing {image1} and {image2}...")

    comparison = analyzer.compare_images(image1, image2)

    print(f"\nComparison Results:")
    print(f"  Added packages: {len(comparison['added'])}")
    print(f"  Removed packages: {len(comparison['removed'])}")
    print(f"  Updated packages: {len(comparison['updated'])}")
    print(f"  Unchanged packages: {comparison['unchanged']}")
    print(f"  Total changes: {comparison['total_changes']}")

    if comparison['added']:
        print(f"\n  Sample added packages:")
        for pkg in comparison['added'][:5]:
            print(f"    + {pkg}")

    if comparison['updated']:
        print(f"\n  Sample updated packages:")
        for pkg in comparison['updated'][:5]:
            print(f"    ~ {pkg['name']}: {pkg['old_version']} -> {pkg['new_version']}")

    analyzer.close()


def example_package_categorization():
    """Example: Categorize packages by type."""
    print("\n" + "=" * 60)
    print("Example: Package Categorization")
    print("=" * 60)

    analyzer = DockerSecurityAnalyzer()

    image = "ubuntu:22.04"
    print(f"\nAnalyzing package categories in {image}...")

    origins = analyzer.analyze_package_origins(image)

    print("\nPackage Categories:")
    for category, count in sorted(origins['categories'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {category}: {count} packages")

    # Show some examples
    if 'security' in origins['details']:
        print("\nSecurity-related packages:")
        for pkg in origins['details']['security'][:5]:
            print(f"  - {pkg}")

    analyzer.close()


def example_multi_image_audit():
    """Example: Audit multiple images."""
    print("\n" + "=" * 60)
    print("Example: Multi-Image Security Audit")
    print("=" * 60)

    analyzer = DockerSecurityAnalyzer()

    images = [
        "alpine:3.18",
        "debian:12",
        "ubuntu:22.04"
    ]

    results = []

    for image in images:
        try:
            print(f"\nAuditing {image}...")
            sbom = analyzer.generate_sbom(image)

            results.append({
                'image': image,
                'distro': sbom['image']['distro'],
                'packages': sbom['metadata']['total_packages'],
                'size_mb': sbom['metadata']['image_size'] / (1024**2) if sbom['metadata']['image_size'] else 0
            })
        except Exception as e:
            print(f"  Error: {e}")

    # Summary report
    print("\n" + "=" * 60)
    print("Audit Summary")
    print("=" * 60)
    print(f"{'Image':<25} {'Distro':<15} {'Packages':<12} {'Size (MB)':<12}")
    print("-" * 64)

    for result in results:
        print(f"{result['image']:<25} {result['distro']:<15} {result['packages']:<12} {result['size_mb']:<12.1f}")

    analyzer.close()


def example_export_package_list():
    """Example: Export package list in various formats."""
    print("\n" + "=" * 60)
    print("Example: Export Package Lists")
    print("=" * 60)

    analyzer = DockerSecurityAnalyzer()

    image = "alpine:3.18"
    print(f"\nExporting package list for {image}...")

    sbom = analyzer.generate_sbom(image)

    # Export as simple text list
    text_output = "/tmp/packages.txt"
    with open(text_output, 'w') as f:
        for pkg in sbom['packages']:
            f.write(f"{pkg['name']} {pkg['version']}\n")
    print(f"Text list saved to {text_output}")

    # Export as CSV
    csv_output = "/tmp/packages.csv"
    with open(csv_output, 'w') as f:
        f.write("name,version,architecture\n")
        for pkg in sbom['packages']:
            arch = pkg['architecture'] or ''
            f.write(f"{pkg['name']},{pkg['version']},{arch}\n")
    print(f"CSV saved to {csv_output}")

    # Export as JSON
    json_output = "/tmp/packages.json"
    with open(json_output, 'w') as f:
        json.dump(sbom, f, indent=2)
    print(f"JSON saved to {json_output}")

    analyzer.close()


if __name__ == "__main__":
    """Run all advanced examples."""
    try:
        # example_vulnerability_check()
        example_sbom_generation()
        # example_image_comparison()
        # example_package_categorization()
        # example_multi_image_audit()
        # example_export_package_list()

        print("\n" + "=" * 60)
        print("All advanced examples completed!")
        print("=" * 60)

    except Exception as e:
        print(f"\nError running examples: {e}")
        print("\nMake sure Docker is running and you have network connectivity.")