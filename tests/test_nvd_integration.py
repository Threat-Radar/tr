"""Tests for NVD integration and CVE matching."""
import pytest
import tempfile
import time
from pathlib import Path
from datetime import datetime

from threat_radar.core.nvd_client import NVDClient, RateLimiter, CVEItem
from threat_radar.core.cve_database import CVEDatabase
from threat_radar.core.cve_matcher import (
    VersionComparator,
    PackageNameMatcher,
    CVEMatcher,
    CVEMatch
)
from threat_radar.core.package_extractors import Package


class TestRateLimiter:
    """Test rate limiting functionality."""

    def test_rate_limiter_allows_requests_within_limit(self):
        """Test that requests within limit are allowed immediately."""
        limiter = RateLimiter(requests_per_interval=5, interval_seconds=10)

        start_time = time.time()
        for _ in range(5):
            limiter.wait_if_needed()
        elapsed = time.time() - start_time

        # Should complete almost instantly
        assert elapsed < 1.0

    def test_rate_limiter_blocks_excess_requests(self):
        """Test that excess requests are rate limited."""
        limiter = RateLimiter(requests_per_interval=3, interval_seconds=2)

        # Make 3 requests (should be instant)
        for _ in range(3):
            limiter.wait_if_needed()

        # 4th request should wait
        start_time = time.time()
        limiter.wait_if_needed()
        elapsed = time.time() - start_time

        # Should have waited approximately 2 seconds
        assert elapsed >= 1.5  # Allow some tolerance


class TestVersionComparator:
    """Test version comparison logic."""

    def test_parse_version_simple(self):
        """Test parsing simple version strings."""
        parts, suffix = VersionComparator.parse_version("1.2.3")
        assert parts == [1, 2, 3]
        assert suffix == ""

    def test_parse_version_with_suffix(self):
        """Test parsing versions with suffixes."""
        parts, suffix = VersionComparator.parse_version("2.0.0-beta")
        assert parts == [2, 0, 0]
        assert suffix == "beta"

    def test_parse_version_with_v_prefix(self):
        """Test parsing versions with 'v' prefix."""
        parts, suffix = VersionComparator.parse_version("v3.1.4")
        assert parts == [3, 1, 4]
        assert suffix == ""

    def test_compare_versions_equal(self):
        """Test comparing equal versions."""
        assert VersionComparator.compare_versions("1.2.3", "1.2.3") == 0
        assert VersionComparator.compare_versions("2.0", "2.0.0") == 0

    def test_compare_versions_less_than(self):
        """Test comparing older versions."""
        assert VersionComparator.compare_versions("1.2.3", "1.2.4") == -1
        assert VersionComparator.compare_versions("1.9", "2.0") == -1
        assert VersionComparator.compare_versions("1.0.0-alpha", "1.0.0") == -1

    def test_compare_versions_greater_than(self):
        """Test comparing newer versions."""
        assert VersionComparator.compare_versions("2.0.0", "1.9.9") == 1
        assert VersionComparator.compare_versions("3.1", "3.0.5") == 1
        assert VersionComparator.compare_versions("1.0.0", "1.0.0-beta") == 1

    def test_version_in_range_inclusive(self):
        """Test version range checking with inclusive bounds."""
        assert VersionComparator.is_version_in_range(
            "2.0.0",
            start_including="2.0.0",
            end_including="3.0.0"
        ) is True

        assert VersionComparator.is_version_in_range(
            "2.5.0",
            start_including="2.0.0",
            end_including="3.0.0"
        ) is True

        assert VersionComparator.is_version_in_range(
            "1.9.0",
            start_including="2.0.0",
            end_including="3.0.0"
        ) is False

    def test_version_in_range_exclusive(self):
        """Test version range checking with exclusive bounds."""
        assert VersionComparator.is_version_in_range(
            "2.0.0",
            start_excluding="2.0.0",
            end_excluding="3.0.0"
        ) is False

        assert VersionComparator.is_version_in_range(
            "2.5.0",
            start_excluding="2.0.0",
            end_excluding="3.0.0"
        ) is True


class TestPackageNameMatcher:
    """Test package name matching and fuzzy matching."""

    def test_normalize_name_removes_prefix(self):
        """Test that common prefixes are removed."""
        assert PackageNameMatcher.normalize_name("libssl") == "ssl"
        assert PackageNameMatcher.normalize_name("python-requests") == "requests"

    def test_normalize_name_removes_suffix(self):
        """Test that common suffixes are removed."""
        assert PackageNameMatcher.normalize_name("openssl-dev") == "openssl"
        assert PackageNameMatcher.normalize_name("curl-bin") == "curl"

    def test_normalize_name_removes_special_chars(self):
        """Test that special characters are removed."""
        assert PackageNameMatcher.normalize_name("my-package_name") == "mypackagename"

    def test_similarity_score_exact_match(self):
        """Test similarity score for exact matches."""
        score = PackageNameMatcher.similarity_score("openssl", "openssl")
        assert score == 1.0

    def test_similarity_score_case_insensitive(self):
        """Test that matching is case insensitive."""
        score = PackageNameMatcher.similarity_score("OpenSSL", "openssl")
        assert score == 1.0

    def test_similarity_score_normalized_match(self):
        """Test similarity score after normalization."""
        score = PackageNameMatcher.similarity_score("libssl", "openssl")
        # Should have high similarity due to "ssl" match
        assert score >= 0.8

    def test_similarity_score_known_mapping(self):
        """Test known package name mappings."""
        score = PackageNameMatcher.similarity_score("log4j", "log4j-core")
        assert score >= 0.9

    def test_similarity_score_different_packages(self):
        """Test similarity score for different packages."""
        score = PackageNameMatcher.similarity_score("nginx", "apache")
        assert score < 0.5

    def test_is_likely_match(self):
        """Test likely match detection."""
        assert PackageNameMatcher.is_likely_match("openssl", "openssl") is True
        assert PackageNameMatcher.is_likely_match("libssl", "openssl-dev") is True
        assert PackageNameMatcher.is_likely_match("nginx", "apache") is False


class TestCVEMatcher:
    """Test CVE matching functionality."""

    def test_calculate_confidence_exact_match_with_version(self):
        """Test confidence calculation for exact name and version match."""
        matcher = CVEMatcher()
        confidence = matcher._calculate_confidence(
            name_similarity=1.0,
            version_match=True,
            has_version=True,
            cvss_score=9.0
        )
        # Should be very high confidence
        assert confidence >= 0.95

    def test_calculate_confidence_name_match_no_version(self):
        """Test confidence calculation when no version info available."""
        matcher = CVEMatcher()
        confidence = matcher._calculate_confidence(
            name_similarity=1.0,
            version_match=False,
            has_version=False,
            cvss_score=7.0
        )
        # Should have moderate confidence
        assert 0.6 <= confidence <= 0.8

    def test_calculate_confidence_version_mismatch(self):
        """Test confidence penalty for version mismatch."""
        matcher = CVEMatcher()
        confidence = matcher._calculate_confidence(
            name_similarity=1.0,
            version_match=False,
            has_version=True,
            cvss_score=5.0
        )
        # Should be penalized for version mismatch
        assert confidence < 0.5

    def test_match_package_with_mock_cve(self):
        """Test package matching with a mock CVE."""
        package = Package(name="openssl", version="1.1.1k", architecture="amd64")

        # Create a mock CVE
        cve = CVEItem(
            cve_id="CVE-2021-TEST",
            published_date="2021-01-01T00:00:00",
            last_modified_date="2021-01-01T00:00:00",
            description="Test vulnerability",
            severity="HIGH",
            cvss_score=8.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            affected_products=[{
                "cpe23Uri": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
                "versionStartIncluding": None,
                "versionStartExcluding": None,
                "versionEndIncluding": None,
                "versionEndExcluding": None,
            }],
            references=[],
            cwe_ids=["CWE-119"]
        )

        matcher = CVEMatcher(min_confidence=0.6)
        matches = matcher.match_package(package, [cve])

        assert len(matches) == 1
        assert matches[0].cve.cve_id == "CVE-2021-TEST"
        assert matches[0].confidence >= 0.8

    def test_bulk_match_packages(self):
        """Test bulk matching of multiple packages."""
        packages = [
            Package(name="openssl", version="1.1.1k", architecture="amd64"),
            Package(name="curl", version="7.68.0", architecture="amd64"),
            Package(name="nginx", version="1.18.0", architecture="amd64"),
        ]

        cve = CVEItem(
            cve_id="CVE-2021-OPENSSL",
            published_date="2021-01-01T00:00:00",
            last_modified_date="2021-01-01T00:00:00",
            description="OpenSSL vulnerability",
            severity="HIGH",
            cvss_score=7.5,
            affected_products=[{
                "cpe23Uri": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
            }]
        )

        matcher = CVEMatcher(min_confidence=0.6)
        results = matcher.bulk_match_packages(packages, [cve])

        # Should only match openssl
        assert "openssl" in results
        assert "curl" not in results
        assert "nginx" not in results


class TestCVEDatabase:
    """Test CVE database functionality."""

    def test_database_initialization(self):
        """Test database initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = CVEDatabase(db_path=str(db_path))

            assert db_path.exists()

            stats = db.get_stats()
            assert stats["total_cves"] == 0

            db.close()

    def test_store_and_retrieve_cve(self):
        """Test storing and retrieving CVEs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = CVEDatabase(db_path=str(db_path))

            # Create test CVE
            cve = CVEItem(
                cve_id="CVE-2021-TEST",
                published_date="2021-01-01T00:00:00",
                last_modified_date="2021-01-01T00:00:00",
                description="Test vulnerability",
                severity="CRITICAL",
                cvss_score=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                affected_products=[],
                references=["https://example.com"],
                cwe_ids=["CWE-119"]
            )

            # Store CVE
            assert db.store_cve(cve) is True

            # Retrieve CVE
            retrieved = db.get_cve("CVE-2021-TEST")
            assert retrieved is not None
            assert retrieved.cve_id == "CVE-2021-TEST"
            assert retrieved.severity == "CRITICAL"
            assert retrieved.cvss_score == 9.8

            db.close()

    def test_search_cves_by_severity(self):
        """Test searching CVEs by severity."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = CVEDatabase(db_path=str(db_path))

            # Store CVEs with different severities
            for i, severity in enumerate(["CRITICAL", "HIGH", "MEDIUM", "LOW"]):
                cve = CVEItem(
                    cve_id=f"CVE-2021-{i:04d}",
                    published_date="2021-01-01T00:00:00",
                    last_modified_date="2021-01-01T00:00:00",
                    description=f"Test {severity}",
                    severity=severity,
                    cvss_score=9.0 - i
                )
                db.store_cve(cve)

            # Search for CRITICAL only
            results = db.search_cves(severity="CRITICAL")
            assert len(results) == 1
            assert results[0].severity == "CRITICAL"

            # Search for minimum CVSS score
            results = db.search_cves(min_cvss_score=7.5)
            assert len(results) >= 2  # CRITICAL and HIGH

            db.close()

    def test_database_stats(self):
        """Test database statistics."""
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test.db"
            db = CVEDatabase(db_path=str(db_path))

            # Add some CVEs
            for i in range(5):
                cve = CVEItem(
                    cve_id=f"CVE-2021-{i:04d}",
                    published_date="2021-01-01T00:00:00",
                    last_modified_date="2021-01-01T00:00:00",
                    description="Test",
                    severity="HIGH"
                )
                db.store_cve(cve)

            stats = db.get_stats()
            assert stats["total_cves"] == 5
            assert "HIGH" in stats["by_severity"]
            assert stats["by_severity"]["HIGH"] == 5

            db.close()


class TestNVDClient:
    """Test NVD API client (requires network access)."""

    @pytest.mark.skip(reason="Requires network access and NVD API")
    def test_get_cve_by_id(self):
        """Test retrieving a specific CVE (network test)."""
        client = NVDClient()

        # Get a well-known CVE (Log4Shell)
        cve = client.get_cve_by_id("CVE-2021-44228")

        assert cve is not None
        assert cve.cve_id == "CVE-2021-44228"
        assert "log4j" in cve.description.lower()
        assert cve.severity is not None
        assert cve.cvss_score is not None

        client.close()

    @pytest.mark.skip(reason="Requires network access and NVD API")
    def test_search_cves_by_keyword(self):
        """Test searching CVEs by keyword (network test)."""
        client = NVDClient()

        cves = client.search_cves(keyword="log4j", results_per_page=10)

        assert len(cves) > 0
        assert any("log4j" in cve.description.lower() for cve in cves)

        client.close()

    def test_cache_functionality(self):
        """Test CVE caching."""
        with tempfile.TemporaryDirectory() as tmpdir:
            client = NVDClient(cache_dir=tmpdir)

            # Create a mock CVE and cache it
            cve = CVEItem(
                cve_id="CVE-2021-CACHE-TEST",
                published_date="2021-01-01T00:00:00",
                last_modified_date="2021-01-01T00:00:00",
                description="Cache test",
                severity="HIGH"
            )

            client._save_to_cache(cve)

            # Retrieve from cache
            cached = client._get_from_cache("CVE-2021-CACHE-TEST")

            assert cached is not None
            assert cached.cve_id == "CVE-2021-CACHE-TEST"
            assert cached.description == "Cache test"

            client.close()
