"""Tests for SBOM-CVE integration functionality."""

import pytest
from pathlib import Path
from threat_radar.core.sbom_package_converter import (
    detect_sbom_format,
    convert_sbom_to_packages,
    get_package_statistics,
)
from threat_radar.core.package_extractors import Package


# Test data
SYFT_SBOM = {
    "artifacts": [
        {
            "name": "openssl",
            "version": "1.1.1",
            "type": "deb",
            "metadata": {"architecture": "amd64"},
        },
        {"name": "curl", "version": "7.64.0", "type": "deb"},
    ],
    "source": {"type": "image"},
    "descriptor": {"name": "syft"},
}

CYCLONEDX_SBOM = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "version": 1,
    "components": [
        {
            "name": "log4j-core",
            "version": "2.14.1",
            "type": "library",
            "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        },
        {
            "name": "openssl",
            "version": "1.0.2k",
            "type": "library",
            "purl": "pkg:deb/debian/openssl@1.0.2k?arch=amd64",
        },
    ],
}

SPDX_SBOM = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-1",
            "name": "nginx",
            "versionInfo": "1.18.0",
            "summary": "Web server",
            "externalRefs": [
                {
                    "referenceType": "purl",
                    "referenceLocator": "pkg:deb/ubuntu/nginx@1.18.0",
                }
            ],
        },
        {"SPDXID": "SPDXRef-Package-2", "name": "python3", "versionInfo": "3.8.10"},
    ],
}


class TestSBOMFormatDetection:
    """Test SBOM format detection."""

    def test_detect_syft_format(self):
        """Test detection of Syft JSON format."""
        format_type = detect_sbom_format(SYFT_SBOM)
        assert format_type == "syft"

    def test_detect_cyclonedx_format(self):
        """Test detection of CycloneDX format."""
        format_type = detect_sbom_format(CYCLONEDX_SBOM)
        assert format_type == "cyclonedx"

    def test_detect_spdx_format(self):
        """Test detection of SPDX format."""
        format_type = detect_sbom_format(SPDX_SBOM)
        assert format_type == "spdx"

    def test_detect_unknown_format(self):
        """Test that unknown format raises ValueError."""
        with pytest.raises(ValueError, match="Unable to detect SBOM format"):
            detect_sbom_format({"unknown": "format"})


class TestSBOMPackageConversion:
    """Test conversion of SBOM packages to Package objects."""

    def test_convert_syft_packages(self):
        """Test conversion of Syft artifacts to packages."""
        packages = convert_sbom_to_packages(SYFT_SBOM, format="syft")

        assert len(packages) == 2
        assert isinstance(packages[0], Package)
        assert packages[0].name == "openssl"
        assert packages[0].version == "1.1.1"
        assert packages[0].architecture == "amd64"
        assert packages[1].name == "curl"
        assert packages[1].version == "7.64.0"

    def test_convert_cyclonedx_packages(self):
        """Test conversion of CycloneDX components to packages."""
        packages = convert_sbom_to_packages(CYCLONEDX_SBOM, format="cyclonedx")

        assert len(packages) == 2
        assert packages[0].name == "log4j-core"
        assert packages[0].version == "2.14.1"
        assert packages[1].name == "openssl"
        assert packages[1].version == "1.0.2k"
        assert packages[1].architecture == "amd64"  # Extracted from purl

    def test_convert_spdx_packages(self):
        """Test conversion of SPDX packages to Package objects."""
        packages = convert_sbom_to_packages(SPDX_SBOM, format="spdx")

        assert len(packages) == 2
        assert packages[0].name == "nginx"
        assert packages[0].version == "1.18.0"
        assert packages[0].description == "Web server"
        assert packages[1].name == "python3"
        assert packages[1].version == "3.8.10"

    def test_auto_detect_format(self):
        """Test automatic format detection during conversion."""
        packages = convert_sbom_to_packages(SYFT_SBOM)
        assert len(packages) == 2

        packages = convert_sbom_to_packages(CYCLONEDX_SBOM)
        assert len(packages) == 2

        packages = convert_sbom_to_packages(SPDX_SBOM)
        assert len(packages) == 2

    def test_filter_by_type(self):
        """Test filtering packages by type."""
        packages = convert_sbom_to_packages(SYFT_SBOM, include_types=["deb"])
        assert len(packages) == 2

        packages = convert_sbom_to_packages(SYFT_SBOM, include_types=["rpm"])
        assert len(packages) == 0

    def test_unsupported_format(self):
        """Test that unsupported format raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported SBOM format"):
            convert_sbom_to_packages({"unknown": "data"}, format="invalid")


class TestPackageStatistics:
    """Test package statistics functionality."""

    def test_get_package_statistics(self):
        """Test getting package type statistics."""
        packages = convert_sbom_to_packages(SYFT_SBOM, format="syft")
        stats = get_package_statistics(packages)

        assert "deb" in stats
        assert stats["deb"] == 2

    def test_mixed_package_types(self):
        """Test statistics with mixed package types."""
        mixed_sbom = {
            "artifacts": [
                {"name": "pkg1", "version": "1.0", "type": "deb"},
                {"name": "pkg2", "version": "2.0", "type": "rpm"},
                {"name": "pkg3", "version": "3.0", "type": "deb"},
                {"name": "pkg4", "version": "4.0", "type": "npm"},
            ],
            "source": {"type": "image"},
            "descriptor": {"name": "syft"},
        }

        packages = convert_sbom_to_packages(mixed_sbom, format="syft")
        stats = get_package_statistics(packages)

        assert stats["deb"] == 2
        assert stats["rpm"] == 1
        assert stats["npm"] == 1


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_sbom(self):
        """Test handling of SBOM with no packages."""
        empty_syft = {
            "artifacts": [],
            "source": {"type": "image"},
            "descriptor": {"name": "syft"},
        }

        packages = convert_sbom_to_packages(empty_syft, format="syft")
        assert len(packages) == 0

    def test_missing_version(self):
        """Test handling of packages without version."""
        sbom_no_version = {
            "artifacts": [{"name": "test-pkg", "type": "deb"}],
            "source": {"type": "image"},
            "descriptor": {"name": "syft"},
        }

        packages = convert_sbom_to_packages(sbom_no_version, format="syft")
        # Package without version should be skipped
        assert len(packages) == 0

    def test_missing_name(self):
        """Test handling of packages without name."""
        sbom_no_name = {
            "artifacts": [{"version": "1.0", "type": "deb"}],
            "source": {"type": "image"},
            "descriptor": {"name": "syft"},
        }

        packages = convert_sbom_to_packages(sbom_no_name, format="syft")
        # Package without name should be skipped
        assert len(packages) == 0

    def test_purl_without_arch(self):
        """Test extraction when purl has no architecture."""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": [
                {
                    "name": "test-pkg",
                    "version": "1.0",
                    "type": "library",
                    "purl": "pkg:deb/debian/test-pkg@1.0",
                }
            ],
        }

        packages = convert_sbom_to_packages(sbom, format="cyclonedx")
        assert len(packages) == 1
        assert packages[0].architecture is None
