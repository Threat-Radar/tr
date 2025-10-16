"""AI analysis storage utilities for automatic report saving."""
import os
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
import json

logger = logging.getLogger(__name__)


class AIAnalysisManager:
    """Manages automatic storage of AI analysis results."""

    DEFAULT_STORAGE_DIR = "storage/ai_analysis"

    def __init__(self, storage_dir: Optional[str] = None):
        """
        Initialize AI analysis storage manager.

        Args:
            storage_dir: Custom storage directory path (default: ./storage/ai_analysis)
        """
        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            # Use storage/ai_analysis in current working directory
            self.storage_dir = Path.cwd() / self.DEFAULT_STORAGE_DIR

        self._ensure_storage_exists()

    def _ensure_storage_exists(self) -> None:
        """Create storage directory if it doesn't exist."""
        try:
            self.storage_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"AI analysis storage directory ready: {self.storage_dir}")
        except Exception as e:
            logger.error(f"Failed to create storage directory: {e}")
            raise

    def generate_filename(
        self,
        target: str,
        analysis_type: str = "analysis",
        extension: str = "json"
    ) -> str:
        """
        Generate a filename for AI analysis results.

        Args:
            target: Analysis target (image name, scan file, etc.)
            analysis_type: Type of analysis (analysis, prioritization, remediation)
            extension: File extension (default: json)

        Returns:
            Filename string

        Examples:
            alpine:3.18 -> alpine_3_18_analysis_2025-01-09_14-30-45.json
            scan.json -> scan_prioritization_2025-01-09_14-30-45.json
        """
        # Clean the target name
        clean_target = self._clean_target_name(target)

        # Generate timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        # Construct filename
        filename = f"{clean_target}_{analysis_type}_{timestamp}.{extension}"

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
        analysis_type: str = "analysis",
        extension: str = "json"
    ) -> Path:
        """
        Get full path for storing AI analysis results.

        Args:
            target: Analysis target
            analysis_type: Type of analysis
            extension: File extension

        Returns:
            Full Path object for the storage file
        """
        filename = self.generate_filename(target, analysis_type, extension)
        return self.storage_dir / filename

    def save_analysis(
        self,
        target: str,
        data: Dict[str, Any],
        analysis_type: str = "analysis"
    ) -> Path:
        """
        Save AI analysis to storage.

        Args:
            target: Analysis target
            data: Analysis data (dict to be saved as JSON)
            analysis_type: Type of analysis

        Returns:
            Path to saved file
        """
        file_path = self.get_storage_path(target, analysis_type)

        try:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)

            logger.info(f"Saved AI analysis to: {file_path}")
            return file_path

        except Exception as e:
            logger.error(f"Failed to save AI analysis: {e}")
            raise

    def list_analyses(
        self,
        analysis_type: Optional[str] = None,
        limit: Optional[int] = None
    ) -> list:
        """
        List all AI analyses in storage.

        Args:
            analysis_type: Filter by analysis type (analysis, prioritization, remediation)
            limit: Maximum number of analyses to return

        Returns:
            List of analysis file paths, sorted by modification time (newest first)
        """
        try:
            # Get all JSON files
            all_analyses = list(self.storage_dir.glob("*.json"))

            # Filter by analysis type if specified
            if analysis_type:
                all_analyses = [
                    a for a in all_analyses
                    if f"_{analysis_type}_" in a.name
                ]

            # Sort by modification time (newest first)
            all_analyses.sort(key=lambda p: p.stat().st_mtime, reverse=True)

            # Apply limit if specified
            if limit:
                all_analyses = all_analyses[:limit]

            return all_analyses

        except Exception as e:
            logger.error(f"Failed to list analyses: {e}")
            return []

    def get_storage_stats(self) -> dict:
        """
        Get statistics about stored AI analyses.

        Returns:
            Dictionary with storage statistics
        """
        try:
            analyses = self.list_analyses()

            # Calculate total size
            total_size = sum(a.stat().st_size for a in analyses)

            # Count by type
            type_counts = {}
            for analysis in analyses:
                if "_analysis_" in analysis.name:
                    type_counts["analysis"] = type_counts.get("analysis", 0) + 1
                elif "_prioritization_" in analysis.name:
                    type_counts["prioritization"] = type_counts.get("prioritization", 0) + 1
                elif "_remediation_" in analysis.name:
                    type_counts["remediation"] = type_counts.get("remediation", 0) + 1

            return {
                "storage_dir": str(self.storage_dir),
                "total_analyses": len(analyses),
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "by_type": type_counts,
                "newest_analysis": str(analyses[0]) if analyses else None,
                "oldest_analysis": str(analyses[-1]) if analyses else None,
            }

        except Exception as e:
            logger.error(f"Failed to get storage stats: {e}")
            return {
                "storage_dir": str(self.storage_dir),
                "total_analyses": 0,
                "error": str(e)
            }

    def cleanup_old_analyses(
        self,
        days: int = 30,
        keep_latest: int = 10
    ) -> int:
        """
        Clean up old AI analyses.

        Args:
            days: Remove analyses older than this many days
            keep_latest: Always keep this many latest analyses

        Returns:
            Number of analyses removed
        """
        import time

        try:
            all_analyses = self.list_analyses()

            if len(all_analyses) <= keep_latest:
                logger.info(f"Skipping cleanup - only {len(all_analyses)} analyses (keep_latest={keep_latest})")
                return 0

            # Keep the latest N analyses
            analyses_to_check = all_analyses[keep_latest:]

            # Calculate cutoff time
            cutoff_time = time.time() - (days * 24 * 60 * 60)

            removed = 0
            for analysis in analyses_to_check:
                if analysis.stat().st_mtime < cutoff_time:
                    analysis.unlink()
                    removed += 1
                    logger.debug(f"Removed old analysis: {analysis.name}")

            logger.info(f"Cleaned up {removed} old AI analyses")
            return removed

        except Exception as e:
            logger.error(f"Failed to cleanup analyses: {e}")
            return 0


def get_ai_storage(storage_dir: Optional[str] = None) -> AIAnalysisManager:
    """
    Get AI analysis storage manager instance.

    Args:
        storage_dir: Custom storage directory (default: ./storage/ai_analysis)

    Returns:
        AIAnalysisManager instance
    """
    return AIAnalysisManager(storage_dir)
