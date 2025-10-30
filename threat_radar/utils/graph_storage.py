"""Graph storage management utilities."""

import logging
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict
import json

logger = logging.getLogger(__name__)


class GraphStorageManager:
    """
    Manage graph storage operations.

    Follows the same pattern as CVE and AI storage managers.
    """

    def __init__(self, storage_dir: str = "./storage/graph_storage"):
        """
        Initialize graph storage manager.

        Args:
            storage_dir: Directory to store graph files
        """
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Initialized graph storage: {self.storage_dir}")

    def save_graph(
        self,
        graph_client,
        name: str,
        metadata: Optional[Dict] = None
    ) -> Path:
        """
        Save graph to storage with timestamped filename.

        Args:
            graph_client: GraphClient instance to save
            name: Base name for the graph file
            metadata: Optional metadata to save alongside graph

        Returns:
            Path to saved graph file
        """
        # Sanitize name for filesystem
        safe_name = name.replace(":", "_").replace("/", "_")
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"{safe_name}_{timestamp}.graphml"
        filepath = self.storage_dir / filename

        # Save graph
        graph_client.save(str(filepath))

        # Save metadata if provided
        if metadata:
            metadata_path = filepath.with_suffix(".json")
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
            logger.info(f"Saved graph metadata: {metadata_path}")

        logger.info(f"Saved graph: {filepath}")
        return filepath

    def load_graph(self, filepath: str):
        """
        Load graph from storage.

        Args:
            filepath: Path to graph file

        Returns:
            Loaded NetworkXClient instance
        """
        from ..graph import NetworkXClient

        if not Path(filepath).exists():
            raise FileNotFoundError(f"Graph file not found: {filepath}")

        client = NetworkXClient()
        client.load(filepath)

        logger.info(f"Loaded graph: {filepath}")
        return client

    def list_graphs(self, pattern: str = "*.graphml") -> List[Path]:
        """
        List all stored graphs.

        Args:
            pattern: Glob pattern to filter files

        Returns:
            List of graph file paths sorted by modification time (newest first)
        """
        graphs = sorted(
            self.storage_dir.glob(pattern),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        return graphs

    def get_latest_graph(self, name_filter: Optional[str] = None) -> Optional[Path]:
        """
        Get the most recently saved graph.

        Args:
            name_filter: Optional filter for graph names

        Returns:
            Path to latest graph file or None if no graphs found
        """
        pattern = f"{name_filter}*.graphml" if name_filter else "*.graphml"
        graphs = self.list_graphs(pattern)
        return graphs[0] if graphs else None

    def delete_graph(self, filepath: str) -> bool:
        """
        Delete a graph file and its metadata.

        Args:
            filepath: Path to graph file to delete

        Returns:
            True if deleted successfully
        """
        path = Path(filepath)
        if not path.exists():
            logger.warning(f"Graph file not found: {filepath}")
            return False

        # Delete graph file
        path.unlink()

        # Delete metadata if exists
        metadata_path = path.with_suffix(".json")
        if metadata_path.exists():
            metadata_path.unlink()

        logger.info(f"Deleted graph: {filepath}")
        return True

    def get_storage_stats(self) -> Dict:
        """
        Get storage statistics.

        Returns:
            Dictionary with storage statistics
        """
        graphs = self.list_graphs()
        total_size = sum(g.stat().st_size for g in graphs)

        return {
            "total_graphs": len(graphs),
            "total_size_bytes": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "storage_dir": str(self.storage_dir),
        }

    def cleanup_old_graphs(self, days: int = 30) -> int:
        """
        Delete graphs older than specified days.

        Args:
            days: Delete graphs older than this many days

        Returns:
            Number of graphs deleted
        """
        from datetime import timedelta

        cutoff_time = datetime.now() - timedelta(days=days)
        deleted_count = 0

        for graph_path in self.list_graphs():
            mod_time = datetime.fromtimestamp(graph_path.stat().st_mtime)
            if mod_time < cutoff_time:
                self.delete_graph(str(graph_path))
                deleted_count += 1

        logger.info(f"Cleaned up {deleted_count} old graphs (>{days} days)")
        return deleted_count

    def export_graph_metadata(self, filepath: str) -> Dict:
        """
        Extract and return graph metadata without loading full graph.

        Args:
            filepath: Path to graph file

        Returns:
            Dictionary with graph metadata
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Graph file not found: {filepath}")

        metadata = {
            "filename": path.name,
            "size_bytes": path.stat().st_size,
            "size_mb": round(path.stat().st_size / (1024 * 1024), 2),
            "created": datetime.fromtimestamp(path.stat().st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
        }

        # Load additional metadata if JSON exists
        metadata_path = path.with_suffix(".json")
        if metadata_path.exists():
            with open(metadata_path) as f:
                additional_metadata = json.load(f)
                metadata.update(additional_metadata)

        return metadata
