"""Tests for Syft integration."""

import pytest
import json
from pathlib import Path
from threat_radar.core.syft_integration import SyftClient, SBOMFormat, ScanSource
from threat_radar.utils.sbom_utils import (
    save_sbom,
    load_sbom,
    extract_packages,
    compare_sboms,
    get_package_statistics,
    group_components_by_type,
    extract_component_metadata,
    get_files_by_category,
    get_component_details,
    filter_components_by_language,
    get_language_statistics,
)


class TestSyftClient:
    """Test SyftClient functionality."""

    def test_syft_installation(self):
        """Test that Syft is installed and accessible."""
        client = SyftClient()
        assert client.syft_path is not None

    def test_get_supported_ecosystems(self):
        """Test getting supported ecosystems."""
        ecosystems = SyftClient.get_supported_ecosystems()
        assert isinstance(ecosystems, list)
        assert len(ecosystems) > 0
        assert "python" in ecosystems
        assert "javascript" in ecosystems

    def test_scan_directory(self, tmp_path):
        """Test scanning a directory."""
        # Create a sample Python package
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")

        client = SyftClient()
        sbom = client.scan_directory(tmp_path, output_format=SBOMFormat.SYFT_JSON)

        assert isinstance(sbom, dict)
        assert "artifacts" in sbom

    def test_scan_nonexistent_directory(self):
        """Test scanning a non-existent directory raises error."""
        client = SyftClient()

        with pytest.raises(ValueError, match="does not exist"):
            client.scan_directory("/nonexistent/path")

    def test_parse_syft_json(self):
        """Test parsing Syft JSON output."""
        sample_output = {
            "artifacts": [
                {
                    "name": "test-package",
                    "version": "1.0.0",
                    "type": "python",
                    "purl": "pkg:pypi/test-package@1.0.0",
                    "licenses": ["MIT"],
                    "locations": [{"path": "/path/to/package"}],
                }
            ]
        }

        client = SyftClient()
        packages = client.parse_syft_json(sample_output)

        assert len(packages) == 1
        assert packages[0].name == "test-package"
        assert packages[0].version == "1.0.0"
        assert packages[0].type == "python"

    def test_get_package_count(self):
        """Test getting package count from SBOM."""
        sbom_data = {
            "artifacts": [
                {"name": "pkg1", "version": "1.0.0"},
                {"name": "pkg2", "version": "2.0.0"},
            ]
        }

        client = SyftClient()
        count = client.get_package_count(sbom_data)

        assert count == 2


class TestSBOMUtils:
    """Test SBOM utility functions."""

    def test_save_and_load_sbom(self, tmp_path):
        """Test saving and loading SBOM."""
        sbom_data = {
            "bomFormat": "CycloneDX",
            "components": [{"name": "test", "version": "1.0.0"}],
        }

        output_path = tmp_path / "test_sbom.json"
        save_sbom(sbom_data, output_path)

        assert output_path.exists()

        loaded = load_sbom(output_path)
        assert loaded == sbom_data

    def test_extract_packages_cyclonedx(self):
        """Test extracting packages from CycloneDX format."""
        sbom = {
            "components": [
                {"name": "pkg1", "version": "1.0.0"},
                {"name": "pkg2", "version": "2.0.0"},
            ]
        }

        packages = extract_packages(sbom)
        assert len(packages) == 2

    def test_extract_packages_syft_json(self):
        """Test extracting packages from Syft JSON format."""
        sbom = {
            "artifacts": [
                {"name": "pkg1", "version": "1.0.0"},
                {"name": "pkg2", "version": "2.0.0"},
            ]
        }

        packages = extract_packages(sbom)
        assert len(packages) == 2

    def test_compare_sboms(self):
        """Test comparing two SBOMs."""
        sbom1 = {
            "artifacts": [
                {"name": "common", "version": "1.0.0"},
                {"name": "removed", "version": "1.0.0"},
            ]
        }

        sbom2 = {
            "artifacts": [
                {"name": "common", "version": "1.0.0"},
                {"name": "added", "version": "1.0.0"},
            ]
        }

        diff = compare_sboms(sbom1, sbom2)

        assert "common" in diff["common"]
        assert "added" in diff["added"]
        assert "removed" in diff["removed"]

    def test_get_package_statistics(self):
        """Test getting package statistics."""
        sbom = {
            "artifacts": [
                {"name": "pkg1", "type": "python"},
                {"name": "pkg2", "type": "python"},
                {"name": "pkg3", "type": "javascript"},
            ]
        }

        stats = get_package_statistics(sbom)

        assert stats["python"] == 2
        assert stats["javascript"] == 1


class TestSBOMFormats:
    """Test different SBOM formats."""

    def test_sbom_format_enum(self):
        """Test SBOM format enum values."""
        assert SBOMFormat.CYCLONEDX_JSON.value == "cyclonedx-json"
        assert SBOMFormat.SPDX_JSON.value == "spdx-json"
        assert SBOMFormat.SYFT_JSON.value == "syft-json"

    def test_scan_source_enum(self):
        """Test scan source enum values."""
        assert ScanSource.DIRECTORY.value == "dir"
        assert ScanSource.DOCKER_IMAGE.value == "docker"


class TestComponentFeatures:
    """Test new component-related features."""

    def test_group_components_by_type(self):
        """Test grouping components by type."""
        sbom = {
            "components": [
                {"name": "lib1", "type": "library"},
                {"name": "lib2", "type": "library"},
                {"name": "file1", "type": "file"},
                {"name": "app1", "type": "application"},
            ]
        }

        grouped = group_components_by_type(sbom)

        assert "library" in grouped
        assert "file" in grouped
        assert "application" in grouped
        assert len(grouped["library"]) == 2
        assert len(grouped["file"]) == 1

    def test_extract_component_metadata(self):
        """Test extracting metadata from component properties."""
        component = {
            "name": "test-package",
            "properties": [
                {"name": "syft:package:language", "value": "python"},
                {"name": "syft:package:type", "value": "python"},
                {"name": "syft:location:0:path", "value": "/path/to/package"},
            ],
        }

        metadata = extract_component_metadata(component)

        assert metadata["language"] == "python"
        assert metadata["package_type"] == "python"
        assert metadata["location"] == "/path/to/package"

    def test_get_files_by_category(self):
        """Test categorizing file components."""
        sbom = {
            "components": [
                {"name": "package/METADATA", "type": "file"},
                {"name": "package/RECORD", "type": "file"},
                {"name": "README.md", "type": "file"},
                {"name": "config.json", "type": "file"},
                {"name": "source.py", "type": "file"},
            ]
        }

        categories = get_files_by_category(sbom)

        assert "metadata" in categories
        assert "record" in categories
        assert "documentation" in categories
        assert "config" in categories
        assert "source" in categories

    def test_get_component_details(self):
        """Test getting comprehensive component details."""
        component = {
            "name": "test-lib",
            "version": "1.0.0",
            "type": "library",
            "purl": "pkg:pypi/test-lib@1.0.0",
            "author": "Test Author",
            "properties": [{"name": "syft:package:language", "value": "python"}],
        }

        details = get_component_details(component)

        assert details["name"] == "test-lib"
        assert details["version"] == "1.0.0"
        assert details["type"] == "library"
        assert details["language"] == "python"
        assert details["author"] == "Test Author"

    def test_filter_components_by_language(self):
        """Test filtering components by language."""
        sbom = {
            "components": [
                {
                    "name": "python-lib",
                    "properties": [
                        {"name": "syft:package:language", "value": "python"}
                    ],
                },
                {
                    "name": "js-lib",
                    "properties": [
                        {"name": "syft:package:language", "value": "javascript"}
                    ],
                },
            ]
        }

        python_comps = filter_components_by_language(sbom, "python")

        assert len(python_comps) == 1
        assert python_comps[0]["name"] == "python-lib"

    def test_get_language_statistics(self):
        """Test getting language statistics."""
        sbom = {
            "components": [
                {
                    "name": "lib1",
                    "properties": [
                        {"name": "syft:package:language", "value": "python"}
                    ],
                },
                {
                    "name": "lib2",
                    "properties": [
                        {"name": "syft:package:language", "value": "python"}
                    ],
                },
                {
                    "name": "lib3",
                    "properties": [
                        {"name": "syft:package:language", "value": "javascript"}
                    ],
                },
            ]
        }

        stats = get_language_statistics(sbom)

        assert stats["python"] == 2
        assert stats["javascript"] == 1


@pytest.fixture
def sample_sbom_cyclonedx():
    """Fixture for sample CycloneDX SBOM."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "name": "requests",
                "version": "2.31.0",
                "type": "library",
                "purl": "pkg:pypi/requests@2.31.0",
            }
        ],
    }


@pytest.fixture
def sample_sbom_syft():
    """Fixture for sample Syft JSON SBOM."""
    return {
        "artifacts": [
            {
                "name": "requests",
                "version": "2.31.0",
                "type": "python",
                "purl": "pkg:pypi/requests@2.31.0",
                "licenses": ["Apache-2.0"],
                "locations": [{"path": "/usr/lib/python3/site-packages/requests"}],
            }
        ]
    }
