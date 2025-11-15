"""Comprehensive tests for storage managers (CVE, AI, SBOM, Graph)."""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from threat_radar.utils.cve_storage import CVEStorageManager
from threat_radar.utils.ai_storage import AIAnalysisManager
from threat_radar.utils.sbom_storage import SBOMStorageManager
from threat_radar.utils.graph_storage import GraphStorageManager


class TestCVEStorageManager:
    """Test CVE storage manager."""

    def test_initialization_default_dir(self):
        """Test initialization with default directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('pathlib.Path.cwd', return_value=Path(tmpdir)):
                manager = CVEStorageManager()

                expected_path = Path(tmpdir) / "storage" / "cve_storage"
                assert manager.storage_dir == expected_path
                assert manager.storage_dir.exists()

    def test_initialization_custom_dir(self, tmp_path):
        """Test initialization with custom directory."""
        custom_dir = tmp_path / "custom_cve"
        manager = CVEStorageManager(storage_dir=str(custom_dir))

        assert manager.storage_dir == custom_dir
        assert manager.storage_dir.exists()

    def test_ensure_storage_exists(self, tmp_path):
        """Test that storage directory is created."""
        storage_dir = tmp_path / "test_storage"
        assert not storage_dir.exists()

        manager = CVEStorageManager(storage_dir=str(storage_dir))

        assert storage_dir.exists()
        assert storage_dir.is_dir()

    def test_generate_filename_image(self):
        """Test generating filename for image scan."""
        manager = CVEStorageManager()

        filename = manager.generate_filename("alpine:3.18", scan_type="image")

        assert filename.startswith("alpine_3_18_image_")
        assert filename.endswith(".json")
        assert datetime.now().strftime("%Y-%m-%d") in filename

    def test_generate_filename_sbom(self):
        """Test generating filename for SBOM scan."""
        manager = CVEStorageManager()

        filename = manager.generate_filename("my-app-sbom.json", scan_type="sbom")

        assert filename.startswith("my-app-sbom_sbom_")
        assert filename.endswith(".json")

    def test_generate_filename_directory(self):
        """Test generating filename for directory scan."""
        manager = CVEStorageManager()

        filename = manager.generate_filename("./src", scan_type="directory")

        assert filename.startswith("_src_directory_")
        assert filename.endswith(".json")

    def test_clean_target_name_docker_image(self):
        """Test cleaning Docker image name."""
        manager = CVEStorageManager()

        cleaned = manager._clean_target_name("alpine:3.18")
        assert cleaned == "alpine_3_18"

        cleaned = manager._clean_target_name("docker.io/library/python:3.11-slim")
        assert cleaned == "docker_io_library_python_3_11-slim"

    def test_clean_target_name_special_chars(self):
        """Test cleaning name with special characters."""
        manager = CVEStorageManager()

        cleaned = manager._clean_target_name("test@sha256:abc123")
        assert "@" not in cleaned
        assert ":" not in cleaned

    def test_clean_target_name_long_name(self):
        """Test cleaning very long name."""
        manager = CVEStorageManager()

        long_name = "a" * 150
        cleaned = manager._clean_target_name(long_name)

        assert len(cleaned) <= 100

    def test_get_storage_path(self, tmp_path):
        """Test getting storage path for a target."""
        manager = CVEStorageManager(storage_dir=str(tmp_path))

        path = manager.get_storage_path("alpine:3.18", scan_type="image")

        assert path.parent == tmp_path
        assert path.name.startswith("alpine_3_18_image_")
        assert path.suffix == ".json"

    def test_save_scan_result(self, tmp_path):
        """Test saving scan result to storage."""
        manager = CVEStorageManager(storage_dir=str(tmp_path))

        scan_data = {
            "target": "alpine:3.18",
            "vulnerabilities": [
                {"id": "CVE-2023-0001", "severity": "high"}
            ]
        }

        saved_path = manager.save_scan_result(
            target="alpine:3.18",
            scan_result=scan_data,
            scan_type="image"
        )

        assert saved_path.exists()
        assert saved_path.parent == tmp_path

        # Verify content
        with open(saved_path) as f:
            loaded = json.load(f)
            assert loaded["target"] == "alpine:3.18"
            assert len(loaded["vulnerabilities"]) == 1

    def test_list_stored_scans(self, tmp_path):
        """Test listing stored scan results."""
        manager = CVEStorageManager(storage_dir=str(tmp_path))

        # Save multiple scans
        scan_data = {"target": "test", "vulnerabilities": []}

        manager.save_scan_result("alpine:3.18", scan_data, "image")
        manager.save_scan_result("python:3.11", scan_data, "image")

        scans = manager.list_stored_scans()

        assert len(scans) == 2

    def test_list_stored_scans_empty(self, tmp_path):
        """Test listing when no scans are stored."""
        manager = CVEStorageManager(storage_dir=str(tmp_path))

        scans = manager.list_stored_scans()

        assert len(scans) == 0

    def test_get_storage_stats(self, tmp_path):
        """Test getting storage statistics."""
        manager = CVEStorageManager(storage_dir=str(tmp_path))

        # Save some scans
        scan_data = {"target": "test", "vulnerabilities": []}
        manager.save_scan_result("alpine:3.18", scan_data, "image")
        manager.save_scan_result("python:3.11", scan_data, "image")

        stats = manager.get_storage_stats()

        assert stats["total_scans"] == 2
        assert stats["total_size_bytes"] > 0
        assert "storage_dir" in stats


class TestAIAnalysisManager:
    """Test AI analysis storage manager."""

    def test_initialization_default_dir(self):
        """Test initialization with default directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('pathlib.Path.cwd', return_value=Path(tmpdir)):
                manager = AIAnalysisManager()

                expected_path = Path(tmpdir) / "storage" / "ai_analysis"
                assert manager.storage_dir == expected_path
                assert manager.storage_dir.exists()

    def test_initialization_custom_dir(self, tmp_path):
        """Test initialization with custom directory."""
        custom_dir = tmp_path / "custom_ai"
        manager = AIAnalysisManager(storage_dir=str(custom_dir))

        assert manager.storage_dir == custom_dir
        assert manager.storage_dir.exists()

    def test_generate_filename_analysis(self):
        """Test generating filename for analysis."""
        manager = AIAnalysisManager()

        filename = manager.generate_filename("alpine:3.18", analysis_type="analysis")

        assert filename.startswith("alpine_3_18_analysis_")
        assert filename.endswith(".json")

    def test_generate_filename_prioritization(self):
        """Test generating filename for prioritization."""
        manager = AIAnalysisManager()

        filename = manager.generate_filename("scan.json", analysis_type="prioritization")

        assert filename.startswith("scan_prioritization_")
        assert filename.endswith(".json")

    def test_generate_filename_remediation(self):
        """Test generating filename for remediation."""
        manager = AIAnalysisManager()

        filename = manager.generate_filename("results.json", analysis_type="remediation")

        assert filename.startswith("results_remediation_")
        assert filename.endswith(".json")

    def test_save_analysis_result(self, tmp_path):
        """Test saving analysis result."""
        manager = AIAnalysisManager(storage_dir=str(tmp_path))

        analysis_data = {
            "target": "alpine:3.18",
            "analysis": {
                "risk_level": "high",
                "findings": []
            }
        }

        saved_path = manager.save_analysis_result(
            target="alpine:3.18",
            analysis_result=analysis_data,
            analysis_type="analysis"
        )

        assert saved_path.exists()

        # Verify content
        with open(saved_path) as f:
            loaded = json.load(f)
            assert loaded["target"] == "alpine:3.18"
            assert "analysis" in loaded

    def test_list_stored_analyses(self, tmp_path):
        """Test listing stored analyses."""
        manager = AIAnalysisManager(storage_dir=str(tmp_path))

        # Save multiple analyses
        analysis_data = {"target": "test", "analysis": {}}

        manager.save_analysis_result("alpine:3.18", analysis_data, "analysis")
        manager.save_analysis_result("python:3.11", analysis_data, "prioritization")

        analyses = manager.list_stored_analyses()

        assert len(analyses) == 2

    def test_get_storage_stats(self, tmp_path):
        """Test getting storage statistics."""
        manager = AIAnalysisManager(storage_dir=str(tmp_path))

        # Save some analyses
        analysis_data = {"target": "test", "analysis": {}}
        manager.save_analysis_result("alpine:3.18", analysis_data, "analysis")

        stats = manager.get_storage_stats()

        assert stats["total_analyses"] == 1
        assert stats["total_size_bytes"] > 0
        assert "storage_dir" in stats


class TestSBOMStorageManager:
    """Test SBOM storage manager."""

    def test_initialization_default_dir(self):
        """Test initialization with default directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('pathlib.Path.cwd', return_value=Path(tmpdir)):
                manager = SBOMStorageManager()

                expected_path = Path(tmpdir) / "sbom_storage"
                assert manager.storage_dir == expected_path
                assert manager.storage_dir.exists()

    def test_initialization_custom_dir(self, tmp_path):
        """Test initialization with custom directory."""
        custom_dir = tmp_path / "custom_sbom"
        manager = SBOMStorageManager(storage_dir=str(custom_dir))

        assert manager.storage_dir == custom_dir
        assert manager.storage_dir.exists()

    def test_ensure_category_directories(self, tmp_path):
        """Test that category directories are created."""
        manager = SBOMStorageManager(storage_dir=str(tmp_path))

        docker_dir = tmp_path / "docker"
        local_dir = tmp_path / "local"
        comparisons_dir = tmp_path / "comparisons"

        assert docker_dir.exists()
        assert local_dir.exists()
        assert comparisons_dir.exists()

    def test_generate_filename_docker(self):
        """Test generating filename for Docker SBOM."""
        manager = SBOMStorageManager()

        filename = manager.generate_filename("alpine:3.18", category="docker")

        assert filename.startswith("alpine_3_18_")
        assert filename.endswith(".json")

    def test_save_sbom_docker_category(self, tmp_path):
        """Test saving SBOM to Docker category."""
        manager = SBOMStorageManager(storage_dir=str(tmp_path))

        sbom_data = {
            "name": "alpine:3.18",
            "packages": []
        }

        saved_path = manager.save_sbom(
            target="alpine:3.18",
            sbom_data=sbom_data,
            category="docker"
        )

        assert saved_path.exists()
        assert saved_path.parent.name == "docker"

    def test_save_sbom_local_category(self, tmp_path):
        """Test saving SBOM to local category."""
        manager = SBOMStorageManager(storage_dir=str(tmp_path))

        sbom_data = {
            "name": "./my-app",
            "packages": []
        }

        saved_path = manager.save_sbom(
            target="./my-app",
            sbom_data=sbom_data,
            category="local"
        )

        assert saved_path.exists()
        assert saved_path.parent.name == "local"

    def test_list_sboms_by_category(self, tmp_path):
        """Test listing SBOMs filtered by category."""
        manager = SBOMStorageManager(storage_dir=str(tmp_path))

        sbom_data = {"name": "test", "packages": []}

        # Save to different categories
        manager.save_sbom("alpine:3.18", sbom_data, "docker")
        manager.save_sbom("python:3.11", sbom_data, "docker")
        manager.save_sbom("./app", sbom_data, "local")

        docker_sboms = manager.list_sboms(category="docker")
        local_sboms = manager.list_sboms(category="local")

        assert len(docker_sboms) == 2
        assert len(local_sboms) == 1

    def test_list_all_sboms(self, tmp_path):
        """Test listing all SBOMs."""
        manager = SBOMStorageManager(storage_dir=str(tmp_path))

        sbom_data = {"name": "test", "packages": []}

        manager.save_sbom("alpine:3.18", sbom_data, "docker")
        manager.save_sbom("./app", sbom_data, "local")

        all_sboms = manager.list_sboms()

        assert len(all_sboms) == 2

    def test_get_storage_stats(self, tmp_path):
        """Test getting storage statistics."""
        manager = SBOMStorageManager(storage_dir=str(tmp_path))

        sbom_data = {"name": "test", "packages": []}
        manager.save_sbom("alpine:3.18", sbom_data, "docker")

        stats = manager.get_storage_stats()

        assert stats["total_sboms"] == 1
        assert stats["by_category"]["docker"] == 1
        assert stats["total_size_bytes"] > 0


class TestGraphStorageManager:
    """Test graph storage manager (already tested in test_graph_integration.py, adding edge cases)."""

    def test_initialization_default_dir(self):
        """Test initialization with default directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('pathlib.Path.cwd', return_value=Path(tmpdir)):
                manager = GraphStorageManager()

                expected_path = Path(tmpdir) / "storage" / "graph_storage"
                assert manager.storage_dir == expected_path
                assert manager.storage_dir.exists()

    def test_initialization_custom_dir(self, tmp_path):
        """Test initialization with custom directory."""
        custom_dir = tmp_path / "custom_graphs"
        manager = GraphStorageManager(storage_dir=str(custom_dir))

        assert manager.storage_dir == custom_dir
        assert manager.storage_dir.exists()

    def test_generate_filename(self):
        """Test generating graph filename."""
        manager = GraphStorageManager()

        filename = manager.generate_filename("alpine:3.18")

        assert filename.startswith("alpine_3_18_")
        assert filename.endswith(".graphml")

    def test_save_graph_with_metadata(self, tmp_path):
        """Test saving graph with metadata."""
        from threat_radar.graph import NetworkXClient, GraphNode, NodeType

        manager = GraphStorageManager(storage_dir=str(tmp_path))
        client = NetworkXClient()

        # Add some nodes
        client.add_node(GraphNode("test:1", NodeType.CONTAINER, {}))

        metadata = {
            "target": "alpine:3.18",
            "node_count": 1,
            "created_at": datetime.now().isoformat()
        }

        saved_path = manager.save_graph(
            client,
            "alpine:3.18",
            metadata=metadata
        )

        assert saved_path.exists()

        # Check metadata file
        metadata_path = saved_path.with_suffix('.json')
        assert metadata_path.exists()

        with open(metadata_path) as f:
            loaded_metadata = json.load(f)
            assert loaded_metadata["target"] == "alpine:3.18"

    def test_cleanup_old_graphs(self, tmp_path):
        """Test cleaning up old graph files."""
        from threat_radar.graph import NetworkXClient

        manager = GraphStorageManager(storage_dir=str(tmp_path))
        client = NetworkXClient()

        # Save multiple graphs
        for i in range(5):
            manager.save_graph(client, f"test-{i}")

        assert len(list(tmp_path.glob("*.graphml"))) == 5

        # Cleanup with high retention
        manager.cleanup_old_graphs(days=365)
        assert len(list(tmp_path.glob("*.graphml"))) == 5  # Nothing deleted

        # Cleanup with low retention (force delete)
        manager.cleanup_old_graphs(days=-1)
        assert len(list(tmp_path.glob("*.graphml"))) == 0  # All deleted


class TestStorageManagerEdgeCases:
    """Test edge cases and error handling for storage managers."""

    def test_cve_storage_permission_error(self, tmp_path):
        """Test handling permission errors in CVE storage."""
        storage_dir = tmp_path / "readonly"
        storage_dir.mkdir()
        storage_dir.chmod(0o444)  # Read-only

        try:
            with pytest.raises(Exception):
                manager = CVEStorageManager(storage_dir=str(storage_dir))
                manager.save_scan_result("test", {}, "image")
        finally:
            storage_dir.chmod(0o755)  # Restore permissions

    def test_ai_storage_invalid_json(self, tmp_path):
        """Test handling invalid JSON in AI storage."""
        manager = AIAnalysisManager(storage_dir=str(tmp_path))

        # Try to save invalid data
        invalid_data = {"circular": None}
        invalid_data["circular"] = invalid_data  # Circular reference

        with pytest.raises(Exception):
            manager.save_analysis_result("test", invalid_data, "analysis")

    def test_sbom_storage_very_long_filename(self, tmp_path):
        """Test handling very long filenames in SBOM storage."""
        manager = SBOMStorageManager(storage_dir=str(tmp_path))

        # Very long target name
        long_target = "a" * 200
        sbom_data = {"name": "test", "packages": []}

        # Should succeed with truncated filename
        saved_path = manager.save_sbom(long_target, sbom_data, "docker")

        assert saved_path.exists()
        # Filename should be truncated
        assert len(saved_path.stem) <= 150

    def test_graph_storage_concurrent_access(self, tmp_path):
        """Test handling concurrent access to graph storage."""
        from threat_radar.graph import NetworkXClient

        manager = GraphStorageManager(storage_dir=str(tmp_path))
        client = NetworkXClient()

        # Simulate concurrent saves
        paths = []
        for i in range(3):
            path = manager.save_graph(client, "test")
            paths.append(path)

        # All should have unique filenames (due to timestamps)
        assert len(set(paths)) == 3

    def test_storage_manager_unicode_handling(self, tmp_path):
        """Test handling unicode characters in filenames."""
        manager = CVEStorageManager(storage_dir=str(tmp_path))

        # Target with unicode characters
        target = "测试:alpine"
        scan_data = {"target": target, "vulnerabilities": []}

        # Should handle unicode correctly
        saved_path = manager.save_scan_result(target, scan_data, "image")

        assert saved_path.exists()


class TestStorageManagerIntegration:
    """Integration tests for storage managers."""

    def test_complete_cve_workflow(self, tmp_path):
        """Test complete CVE storage workflow."""
        manager = CVEStorageManager(storage_dir=str(tmp_path))

        # Save scan
        scan_data = {
            "target": "alpine:3.18",
            "vulnerabilities": [
                {"id": "CVE-2023-0001", "severity": "high"}
            ]
        }

        saved_path = manager.save_scan_result("alpine:3.18", scan_data, "image")

        # List scans
        scans = manager.list_stored_scans()
        assert len(scans) == 1

        # Get stats
        stats = manager.get_storage_stats()
        assert stats["total_scans"] == 1

        # Load scan back
        with open(saved_path) as f:
            loaded = json.load(f)
            assert loaded["target"] == "alpine:3.18"

    def test_complete_ai_workflow(self, tmp_path):
        """Test complete AI storage workflow."""
        manager = AIAnalysisManager(storage_dir=str(tmp_path))

        # Save analysis
        analysis_data = {
            "target": "alpine:3.18",
            "risk_level": "high",
            "findings": []
        }

        saved_path = manager.save_analysis_result("alpine:3.18", analysis_data, "analysis")

        # List analyses
        analyses = manager.list_stored_analyses()
        assert len(analyses) == 1

        # Get stats
        stats = manager.get_storage_stats()
        assert stats["total_analyses"] == 1

    def test_complete_sbom_workflow(self, tmp_path):
        """Test complete SBOM storage workflow."""
        manager = SBOMStorageManager(storage_dir=str(tmp_path))

        # Save SBOMs to different categories
        sbom_data = {"name": "test", "packages": []}

        manager.save_sbom("alpine:3.18", sbom_data, "docker")
        manager.save_sbom("./app", sbom_data, "local")

        # List by category
        docker_sboms = manager.list_sboms(category="docker")
        local_sboms = manager.list_sboms(category="local")

        assert len(docker_sboms) == 1
        assert len(local_sboms) == 1

        # Get stats
        stats = manager.get_storage_stats()
        assert stats["total_sboms"] == 2
        assert stats["by_category"]["docker"] == 1
        assert stats["by_category"]["local"] == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
