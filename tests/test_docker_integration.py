"""Tests for Docker integration and container analysis."""

import pytest
import docker
from pathlib import Path

from threat_radar.core.docker_integration import DockerClient
from threat_radar.core.container_analyzer import ContainerAnalyzer
from threat_radar.core.package_extractors import (
    APTExtractor,
    APKExtractor,
    YUMExtractor,
    PackageExtractorFactory,
)


@pytest.fixture(scope="module")
def docker_client():
    """Fixture for Docker client."""
    try:
        client = DockerClient()
        yield client
        client.close()
    except Exception as e:
        pytest.skip(f"Docker not available: {e}")


@pytest.fixture(scope="module")
def test_images(docker_client):
    """Build test images from fixtures."""
    fixtures_dir = Path(__file__).parent / "fixtures"
    images = {}

    # Build test images if Dockerfiles exist
    for dockerfile in ["Dockerfile.alpine", "Dockerfile.ubuntu", "Dockerfile.debian"]:
        dockerfile_path = fixtures_dir / dockerfile
        if dockerfile_path.exists():
            distro = dockerfile.replace("Dockerfile.", "")
            tag = f"tr-test-{distro}:latest"

            try:
                # Build image
                image, build_logs = docker_client.client.images.build(
                    path=str(fixtures_dir), dockerfile=dockerfile, tag=tag, rm=True
                )
                images[distro] = tag
            except Exception as e:
                print(f"Failed to build {dockerfile}: {e}")

    yield images

    # Cleanup: remove test images
    for tag in images.values():
        try:
            docker_client.client.images.remove(tag, force=True)
        except Exception as e:
            print(f"Failed to remove image {tag}: {e}")


class TestDockerClient:
    """Test Docker client wrapper."""

    def test_client_connection(self, docker_client):
        """Test that Docker client can connect."""
        assert docker_client.client is not None
        docker_client.client.ping()

    def test_pull_image(self, docker_client):
        """Test pulling a small image."""
        image = docker_client.pull_image("alpine", tag="3.18")
        assert image is not None
        assert "alpine:3.18" in image.tags or any("alpine" in tag for tag in image.tags)

    def test_get_image(self, docker_client):
        """Test getting an existing image."""
        # First pull the image
        docker_client.pull_image("alpine", tag="3.18")

        # Then get it
        image = docker_client.get_image("alpine:3.18")
        assert image is not None

    def test_run_container(self, docker_client):
        """Test running a command in a container."""
        docker_client.pull_image("alpine", tag="3.18")
        output = docker_client.run_container("alpine:3.18", "echo 'test'")
        assert b"test" in output

    def test_inspect_image(self, docker_client):
        """Test inspecting an image."""
        docker_client.pull_image("alpine", tag="3.18")
        info = docker_client.inspect_image("alpine:3.18")

        assert "Id" in info
        assert "Architecture" in info
        assert "Os" in info


class TestPackageExtractors:
    """Test package extractors."""

    def test_apt_extractor(self):
        """Test APT package extractor."""
        extractor = APTExtractor()

        # Simulate dpkg output
        output = b"curl|7.88.1-10|amd64|command line tool for transferring data\n"
        output += b"wget|1.21.3-1|amd64|retrieves files from the web\n"

        packages = extractor.parse_packages(output)

        assert len(packages) == 2
        assert packages[0].name == "curl"
        assert packages[0].version == "7.88.1-10"
        assert packages[0].architecture == "amd64"

    def test_apk_extractor(self):
        """Test APK package extractor."""
        extractor = APKExtractor()

        # Simulate apk output
        output = b"musl-1.2.4-r0\n"
        output += b"busybox-1.36.1-r2\n"
        output += b"alpine-baselayout-3.4.3-r1\n"

        packages = extractor.parse_packages(output)

        assert len(packages) == 3
        assert packages[0].name == "musl"
        assert packages[0].version == "1.2.4-r0"

    def test_yum_extractor(self):
        """Test YUM/RPM package extractor."""
        extractor = YUMExtractor()

        # Simulate rpm output
        output = b"curl|7.76.1-23.el9|x86_64\n"
        output += b"wget|1.21.1-7.el9|x86_64\n"

        packages = extractor.parse_packages(output)

        assert len(packages) == 2
        assert packages[0].name == "curl"
        assert packages[0].version == "7.76.1-23.el9"
        assert packages[0].architecture == "x86_64"

    def test_extractor_factory(self):
        """Test package extractor factory."""
        # Test getting extractors for different distros
        apt_extractor = PackageExtractorFactory.get_extractor("ubuntu")
        assert isinstance(apt_extractor, APTExtractor)

        apk_extractor = PackageExtractorFactory.get_extractor("alpine")
        assert isinstance(apk_extractor, APKExtractor)

        yum_extractor = PackageExtractorFactory.get_extractor("centos")
        assert isinstance(yum_extractor, YUMExtractor)

        # Test unsupported distro
        unknown = PackageExtractorFactory.get_extractor("unknown")
        assert unknown is None


class TestContainerAnalyzer:
    """Test container analyzer."""

    def test_analyzer_initialization(self):
        """Test analyzer can be initialized."""
        try:
            analyzer = ContainerAnalyzer()
            assert analyzer.docker_client is not None
            analyzer.close()
        except Exception as e:
            pytest.skip(f"Docker not available: {e}")

    def test_analyze_alpine(self, docker_client):
        """Test analyzing Alpine Linux container."""
        analyzer = ContainerAnalyzer()

        # Pull and analyze alpine
        docker_client.pull_image("alpine", tag="3.18")
        analysis = analyzer.analyze_container("alpine:3.18")

        assert analysis is not None
        assert analysis.image_name == "alpine:3.18"
        assert analysis.distro == "alpine"
        assert len(analysis.packages) > 0

        # Check that we got some expected Alpine packages
        package_names = [p.name for p in analysis.packages]
        assert "musl" in package_names or "busybox" in package_names

        analyzer.close()

    def test_analyze_ubuntu(self, test_images):
        """Test analyzing Ubuntu container."""
        if "ubuntu" not in test_images:
            pytest.skip("Ubuntu test image not available")

        analyzer = ContainerAnalyzer()
        analysis = analyzer.analyze_container(test_images["ubuntu"])

        assert analysis is not None
        assert analysis.distro in ["ubuntu", "debian"]
        assert len(analysis.packages) > 0

        # Check that we got some expected packages
        package_names = [p.name for p in analysis.packages]
        assert any(pkg in package_names for pkg in ["curl", "wget", "git"])

        analyzer.close()

    def test_analyze_debian(self, test_images):
        """Test analyzing Debian container."""
        if "debian" not in test_images:
            pytest.skip("Debian test image not available")

        analyzer = ContainerAnalyzer()
        analysis = analyzer.analyze_container(test_images["debian"])

        assert analysis is not None
        assert analysis.distro == "debian"
        assert len(analysis.packages) > 0

        analyzer.close()

    def test_list_images(self, docker_client):
        """Test listing Docker images."""
        analyzer = ContainerAnalyzer()
        images = analyzer.list_analyzed_images()

        assert isinstance(images, list)
        # Should have at least the alpine image we pulled
        assert len(images) > 0

        analyzer.close()

    def test_analysis_to_dict(self, docker_client):
        """Test converting analysis to dictionary."""
        from dataclasses import asdict

        analyzer = ContainerAnalyzer()
        docker_client.pull_image("alpine", tag="3.18")
        analysis = analyzer.analyze_container("alpine:3.18")

        result_dict = asdict(analysis)

        assert isinstance(result_dict, dict)
        assert "image_name" in result_dict
        assert "packages" in result_dict
        assert isinstance(result_dict["packages"], list)

        if result_dict["packages"]:
            assert "name" in result_dict["packages"][0]
            assert "version" in result_dict["packages"][0]

        analyzer.close()


class TestIntegration:
    """Integration tests."""

    def test_full_workflow(self, docker_client):
        """Test complete workflow: import, analyze, extract packages."""
        analyzer = ContainerAnalyzer()

        # Import a small image
        analysis = analyzer.import_container("alpine", tag="3.18")

        # Verify analysis results
        assert analysis.image_name == "alpine:3.18"
        assert analysis.image_id is not None
        assert analysis.distro == "alpine"
        assert len(analysis.packages) > 0

        # Verify package data structure
        first_pkg = analysis.packages[0]
        assert first_pkg.name is not None
        assert first_pkg.version is not None

        # Verify asdict conversion
        from dataclasses import asdict

        result = asdict(analysis)
        assert "packages" in result
        assert len(result["packages"]) == len(analysis.packages)

        analyzer.close()
