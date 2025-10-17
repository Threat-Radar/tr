"""CVE storage utilities for automatic report saving."""
import os
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class CVEStorageManager:
    """Manages automatic storage of CVE scan results."""

    DEFAULT_STORAGE_DIR = "storage/cve_storage"

    def __init__(self, storage_dir: Optional[str] = None):
        """
        Initialize CVE storage manager.

        Args:
            storage_dir: Custom storage directory path (default: ./storage/cve_storage)
        """
        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            # Use storage/cve_storage in current working directory
            self.storage_dir = Path.cwd() / self.DEFAULT_STORAGE_DIR

        self._ensure_storage_exists()

    def _ensure_storage_exists(self) -> None:
        """Create storage directory if it doesn't exist."""
        try:
            self.storage_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"CVE storage directory ready: {self.storage_dir}")
        except Exception as e:
            logger.error(f"Failed to create storage directory: {e}")
            raise

    def generate_filename(
        self,
        target: str,
        scan_type: str = "image",
        extension: str = "json"
    ) -> str:
        """
        Generate a filename for CVE scan results.

        Args:
            target: Scan target (image name, sbom file, directory)
            scan_type: Type of scan (image, sbom, directory)
            extension: File extension (default: json)

        Returns:
            Filename string

        Examples:
            alpine:3.18 -> alpine_3.18_image_2025-01-09_14-30-45.json
            my-app-sbom.json -> my-app-sbom_sbom_2025-01-09_14-30-45.json
        """
        # Clean the target name
        clean_target = self._clean_target_name(target)

        # Generate timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        # Construct filename
        filename = f"{clean_target}_{scan_type}_{timestamp}.{extension}"

        return filename

    def _clean_target_name(self, target: str) -> str:
        """
        Clean target name for use in filename.

        Args:
            target: Target name to clean

        Returns:
            Cleaned name safe for filesystem
        """
        # Remove or replace problematic characters
        clean = target.replace(":", "_")  # Docker image tags
        clean = clean.replace("/", "_")   # Paths and registry prefixes
        clean = clean.replace("@", "_")   # Digests
        clean = clean.replace(" ", "_")   # Spaces
        clean = clean.replace(".", "_")   # Dots (except extension)

        # Remove leading/trailing underscores
        clean = clean.strip("_")

        # Limit length to avoid filesystem issues
        if len(clean) > 100:
            clean = clean[:100]

        return clean

    def get_storage_path(
        self,
        target: str,
        scan_type: str = "image",
        extension: str = "json"
    ) -> Path:
        """
        Get full path for storing CVE scan results.

        Args:
            target: Scan target
            scan_type: Type of scan
            extension: File extension

        Returns:
            Full Path object for the storage file
        """
        filename = self.generate_filename(target, scan_type, extension)
        return self.storage_dir / filename

    def save_report(
        self,
        data: dict,
        target: str,
        scan_type: str = "image"
    ) -> Path:
        """
        Save CVE scan report to storage.

        Args:
            data: Report data (dict to be saved as JSON)
            target: Scan target
            scan_type: Type of scan

        Returns:
            Path to saved file
        """
        import json

        file_path = self.get_storage_path(target, scan_type)

        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)

            logger.info(f"Saved CVE report to: {file_path}")
            return file_path

        except Exception as e:
            logger.error(f"Failed to save CVE report: {e}")
            raise

    def list_reports(
        self,
        scan_type: Optional[str] = None,
        limit: Optional[int] = None
    ) -> list:
        """
        List all CVE reports in storage.

        Args:
            scan_type: Filter by scan type (image, sbom, directory)
            limit: Maximum number of reports to return

        Returns:
            List of report file paths, sorted by modification time (newest first)
        """
        try:
            # Get all JSON files
            all_reports = list(self.storage_dir.glob("*.json"))

            # Filter by scan type if specified
            if scan_type:
                all_reports = [
                    r for r in all_reports
                    if f"_{scan_type}_" in r.name
                ]

            # Sort by modification time (newest first)
            all_reports.sort(key=lambda p: p.stat().st_mtime, reverse=True)

            # Apply limit if specified
            if limit:
                all_reports = all_reports[:limit]

            return all_reports

        except Exception as e:
            logger.error(f"Failed to list reports: {e}")
            return []

    def get_storage_stats(self) -> dict:
        """
        Get statistics about stored CVE reports.

        Returns:
            Dictionary with storage statistics
        """
        try:
            reports = self.list_reports()

            # Calculate total size
            total_size = sum(r.stat().st_size for r in reports)

            # Count by type
            type_counts = {}
            for report in reports:
                if "_image_" in report.name:
                    type_counts["image"] = type_counts.get("image", 0) + 1
                elif "_sbom_" in report.name:
                    type_counts["sbom"] = type_counts.get("sbom", 0) + 1
                elif "_directory_" in report.name:
                    type_counts["directory"] = type_counts.get("directory", 0) + 1

            return {
                "storage_dir": str(self.storage_dir),
                "total_reports": len(reports),
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "by_type": type_counts,
                "newest_report": str(reports[0]) if reports else None,
                "oldest_report": str(reports[-1]) if reports else None,
            }

        except Exception as e:
            logger.error(f"Failed to get storage stats: {e}")
            return {
                "storage_dir": str(self.storage_dir),
                "total_reports": 0,
                "error": str(e)
            }

    def cleanup_old_reports(
        self,
        days: int = 30,
        keep_latest: int = 10
    ) -> int:
        """
        Clean up old CVE reports.

        Args:
            days: Remove reports older than this many days
            keep_latest: Always keep this many latest reports

        Returns:
            Number of reports removed
        """
        import time

        try:
            all_reports = self.list_reports()

            if len(all_reports) <= keep_latest:
                logger.info(f"Skipping cleanup - only {len(all_reports)} reports (keep_latest={keep_latest})")
                return 0

            # Keep the latest N reports
            reports_to_check = all_reports[keep_latest:]

            # Calculate cutoff time
            cutoff_time = time.time() - (days * 24 * 60 * 60)

            removed = 0
            for report in reports_to_check:
                if report.stat().st_mtime < cutoff_time:
                    report.unlink()
                    removed += 1
                    logger.debug(f"Removed old report: {report.name}")

            logger.info(f"Cleaned up {removed} old CVE reports")
            return removed

        except Exception as e:
            logger.error(f"Failed to cleanup reports: {e}")
            return 0


def get_cve_storage(storage_dir: Optional[str] = None) -> CVEStorageManager:
    """
    Get CVE storage manager instance.

    Args:
        storage_dir: Custom storage directory (default: ./cve_storage)

    Returns:
        CVEStorageManager instance
    """
    return CVEStorageManager(storage_dir)
