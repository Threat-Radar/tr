"""Example: Generating CycloneDX SBOMs for Python packages in Docker images."""
import json
from threat_radar.core.docker_integration import DockerClient
from threat_radar.core.python_sbom import PythonPackageExtractor


def example_extract_pip_packages():
    """Example: Extract pip packages from a Python image."""
    print("=" * 60)
    print("Example 1: Extract Pip Packages")
    print("=" * 60)

    docker_client = DockerClient()
    extractor = PythonPackageExtractor(docker_client)

    # Analyze Python image
    image = "python:3.11-slim"
    print(f"\nExtracting pip packages from {image}...")

    packages = extractor.extract_pip_packages(image)

    print(f"\nFound {len(packages)} Python packages:")
    for pkg in packages:
        print(f"  - {pkg.name} {pkg.version}")

    docker_client.close()


def example_generate_cyclonedx():
    """Example: Generate CycloneDX SBOM."""
    print("\n" + "=" * 60)
    print("Example 2: Generate CycloneDX SBOM")
    print("=" * 60)

    docker_client = DockerClient()
    extractor = PythonPackageExtractor(docker_client)

    image = "python:3.11-slim"
    print(f"\nGenerating CycloneDX SBOM for {image}...")

    # Generate SBOM
    sbom = extractor.generate_cyclonedx_from_image(image)

    # Save to file
    output_file = "/tmp/python_sbom.json"
    with open(output_file, 'w') as f:
        json.dump(sbom, f, indent=2)

    print(f"\nSBOM saved to {output_file}")
    print(f"Format: {sbom['bomFormat']} {sbom['specVersion']}")
    print(f"Components: {len(sbom['components'])}")

    # Show sample
    if sbom['components']:
        print("\nSample components:")
        for component in sbom['components'][:5]:
            print(f"  - {component['name']} {component['version']}")
            print(f"    PURL: {component['purl']}")

    docker_client.close()


def example_compare_base_images():
    """Example: Compare Python packages across base images."""
    print("\n" + "=" * 60)
    print("Example 3: Compare Base Images")
    print("=" * 60)

    docker_client = DockerClient()
    extractor = PythonPackageExtractor(docker_client)

    images = [
        "python:3.11-slim",
        "python:3.11-alpine",
        "python:3.10-slim",
    ]

    results = {}

    for image in images:
        print(f"\nAnalyzing {image}...")
        try:
            packages = extractor.extract_pip_packages(image)
            results[image] = {
                'count': len(packages),
                'packages': {pkg.name: pkg.version for pkg in packages}
            }
        except Exception as e:
            print(f"  Error: {e}")
            results[image] = {'count': 0, 'packages': {}}

    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"{'Image':<25} {'Packages':<10}")
    print("-" * 35)

    for image, data in results.items():
        print(f"{image:<25} {data['count']:<10}")

    # Find common packages
    if len(results) >= 2:
        all_packages = [set(data['packages'].keys()) for data in results.values()]
        common = set.intersection(*all_packages)

        print(f"\nCommon packages across all images: {len(common)}")
        for pkg in sorted(common):
            versions = [results[img]['packages'][pkg] for img in images if pkg in results[img]['packages']]
            print(f"  - {pkg}: {', '.join(set(versions))}")

    docker_client.close()


def example_save_multiple_formats():
    """Example: Export SBOM in multiple formats."""
    print("\n" + "=" * 60)
    print("Example 4: Export in Multiple Formats")
    print("=" * 60)

    docker_client = DockerClient()
    extractor = PythonPackageExtractor(docker_client)

    image = "python:3.11-slim"
    print(f"\nAnalyzing {image}...")

    packages = extractor.extract_pip_packages(image)

    # CycloneDX JSON
    cyclonedx = extractor.generate_cyclonedx_sbom(image, packages)
    with open("/tmp/sbom_cyclonedx.json", 'w') as f:
        json.dump(cyclonedx, f, indent=2)
    print("✓ CycloneDX JSON: /tmp/sbom_cyclonedx.json")

    # Simple CSV
    with open("/tmp/sbom_packages.csv", 'w') as f:
        f.write("name,version,location\n")
        for pkg in packages:
            f.write(f"{pkg.name},{pkg.version},{pkg.location or ''}\n")
    print("✓ CSV: /tmp/sbom_packages.csv")

    # Simple text list
    with open("/tmp/sbom_packages.txt", 'w') as f:
        for pkg in packages:
            f.write(f"{pkg.name}=={pkg.version}\n")
    print("✓ Requirements format: /tmp/sbom_packages.txt")

    docker_client.close()


def example_analyze_app_image():
    """Example: Analyze a real application image with dependencies."""
    print("\n" + "=" * 60)
    print("Example 5: Analyze Application Image")
    print("=" * 60)

    # Note: This example requires building a test image first
    print("\nTo test with a real app:")
    print("1. Create a Dockerfile:")
    print("   FROM python:3.11-slim")
    print("   RUN pip install django requests flask")
    print("")
    print("2. Build it:")
    print("   docker build -t my-python-app .")
    print("")
    print("3. Analyze it:")
    print("   (This script will then extract all installed packages)")

    # For demo, use base image
    docker_client = DockerClient()
    extractor = PythonPackageExtractor(docker_client)

    image = "python:3.11-slim"
    print(f"\nDemo with {image}...")

    sbom = extractor.generate_cyclonedx_from_image(image)

    print(f"\nCycloneDX SBOM generated:")
    print(f"  Format: {sbom['bomFormat']} v{sbom['specVersion']}")
    print(f"  Components: {len(sbom['components'])}")
    print(f"  Container: {sbom['metadata']['component']['name']}")

    docker_client.close()


if __name__ == "__main__":
    """Run all examples."""
    try:
        example_extract_pip_packages()
        example_generate_cyclonedx()
        example_compare_base_images()
        example_save_multiple_formats()
        example_analyze_app_image()

        print("\n" + "=" * 60)
        print("All Python SBOM examples completed!")
        print("=" * 60)

    except Exception as e:
        print(f"\nError running examples: {e}")
        print("\nMake sure Docker is running and has connectivity.")
