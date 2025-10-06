"""CVE database with incremental updates and local storage."""
import json
import sqlite3
import logging
from typing import List, Optional, Set
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import asdict

from .nvd_client import NVDClient, CVEItem

logger = logging.getLogger(__name__)


class CVEDatabase:
    """Local CVE database with incremental update capabilities."""

    def __init__(self, db_path: Optional[str] = None, nvd_client: Optional[NVDClient] = None):
        """
        Initialize CVE database.

        Args:
            db_path: Path to SQLite database file (default: ~/.threat_radar/cve.db)
            nvd_client: NVD client instance (optional, will create if not provided)
        """
        if db_path:
            self.db_path = Path(db_path)
        else:
            db_dir = Path.home() / ".threat_radar"
            db_dir.mkdir(parents=True, exist_ok=True)
            self.db_path = db_dir / "cve.db"

        self.nvd_client = nvd_client or NVDClient()
        self._init_database()

        logger.info(f"CVE database initialized at {self.db_path}")

    def _init_database(self) -> None:
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Main CVE table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cves (
                    cve_id TEXT PRIMARY KEY,
                    published_date TEXT NOT NULL,
                    last_modified_date TEXT NOT NULL,
                    description TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    cwe_ids TEXT,
                    reference_urls TEXT,
                    affected_products TEXT,
                    raw_data TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Index for efficient queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_last_modified
                ON cves(last_modified_date)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_severity
                ON cves(severity)
            """)

            # Metadata table for tracking updates
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS update_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            conn.commit()

    def update_from_nvd(self, days: int = 7, force: bool = False) -> int:
        """
        Incrementally update database with recent CVEs from NVD.

        Args:
            days: Number of days to look back for updates
            force: Force update even if recently updated

        Returns:
            Number of CVEs added/updated
        """
        # Check last update time
        if not force:
            last_update = self._get_last_update_time()
            if last_update:
                time_since_update = datetime.now() - last_update
                if time_since_update < timedelta(hours=1):
                    logger.info(f"Database recently updated ({time_since_update} ago), skipping")
                    return 0

        logger.info(f"Fetching CVEs modified in last {days} days...")

        cve_items = self.nvd_client.get_recent_cves(days=days)

        if not cve_items:
            logger.warning("No CVEs retrieved from NVD")
            return 0

        # Store CVEs in database
        updated_count = 0
        for cve in cve_items:
            if self.store_cve(cve):
                updated_count += 1

        # Update metadata
        self._set_last_update_time()

        logger.info(f"Database updated with {updated_count} CVEs")
        return updated_count

    def store_cve(self, cve: CVEItem) -> bool:
        """
        Store or update a CVE in the database.

        Args:
            cve: CVEItem to store

        Returns:
            True if inserted/updated, False otherwise
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            try:
                # Convert lists to JSON strings
                cwe_ids_json = json.dumps(cve.cwe_ids)
                references_json = json.dumps(cve.references)
                affected_products_json = json.dumps(cve.affected_products)
                raw_data_json = json.dumps(cve.raw_data) if cve.raw_data else None

                cursor.execute("""
                    INSERT OR REPLACE INTO cves
                    (cve_id, published_date, last_modified_date, description,
                     severity, cvss_score, cvss_vector, cwe_ids, reference_urls,
                     affected_products, raw_data, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (
                    cve.cve_id,
                    cve.published_date,
                    cve.last_modified_date,
                    cve.description,
                    cve.severity,
                    cve.cvss_score,
                    cve.cvss_vector,
                    cwe_ids_json,
                    references_json,
                    affected_products_json,
                    raw_data_json
                ))

                conn.commit()
                return True

            except sqlite3.Error as e:
                logger.error(f"Failed to store {cve.cve_id}: {e}")
                return False

    def get_cve(self, cve_id: str) -> Optional[CVEItem]:
        """
        Retrieve a CVE from the database.

        Args:
            cve_id: CVE identifier

        Returns:
            CVEItem or None if not found
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM cves WHERE cve_id = ?", (cve_id,))
            row = cursor.fetchone()

            if not row:
                return None

            return self._row_to_cve_item(row)

    def search_cves(
        self,
        severity: Optional[str] = None,
        min_cvss_score: Optional[float] = None,
        keyword: Optional[str] = None,
        limit: int = 100
    ) -> List[CVEItem]:
        """
        Search CVEs in local database.

        Args:
            severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)
            min_cvss_score: Minimum CVSS score
            keyword: Search in description
            limit: Maximum results to return

        Returns:
            List of CVEItem objects
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = "SELECT * FROM cves WHERE 1=1"
            params: List = []

            if severity:
                query += " AND severity = ?"
                params.append(severity.upper())

            if min_cvss_score is not None:
                query += " AND cvss_score >= ?"
                params.append(min_cvss_score)

            if keyword:
                query += " AND description LIKE ?"
                params.append(f"%{keyword}%")

            query += " ORDER BY last_modified_date DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()

            return [self._row_to_cve_item(row) for row in rows]

    def get_stats(self) -> dict:
        """Get database statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            stats = {}

            # Total CVEs
            cursor.execute("SELECT COUNT(*) FROM cves")
            stats["total_cves"] = cursor.fetchone()[0]

            # By severity
            cursor.execute("""
                SELECT severity, COUNT(*)
                FROM cves
                WHERE severity IS NOT NULL
                GROUP BY severity
            """)
            stats["by_severity"] = {row[0]: row[1] for row in cursor.fetchall()}

            # Last update time
            stats["last_update"] = self._get_last_update_time()

            # Date range
            cursor.execute("SELECT MIN(published_date), MAX(published_date) FROM cves")
            row = cursor.fetchone()
            stats["date_range"] = {"earliest": row[0], "latest": row[1]}

            return stats

    def _row_to_cve_item(self, row: sqlite3.Row) -> CVEItem:
        """Convert database row to CVEItem."""
        return CVEItem(
            cve_id=row["cve_id"],
            published_date=row["published_date"],
            last_modified_date=row["last_modified_date"],
            description=row["description"],
            severity=row["severity"],
            cvss_score=row["cvss_score"],
            cvss_vector=row["cvss_vector"],
            cwe_ids=json.loads(row["cwe_ids"]) if row["cwe_ids"] else [],
            references=json.loads(row["reference_urls"]) if row["reference_urls"] else [],
            affected_products=json.loads(row["affected_products"]) if row["affected_products"] else [],
            raw_data=json.loads(row["raw_data"]) if row["raw_data"] else None
        )

    def _get_last_update_time(self) -> Optional[datetime]:
        """Get the last database update timestamp."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT value FROM update_metadata WHERE key = 'last_update'"
            )
            row = cursor.fetchone()

            if row:
                return datetime.fromisoformat(row[0])
            return None

    def _set_last_update_time(self) -> None:
        """Set the last database update timestamp."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO update_metadata (key, value, updated_at)
                VALUES ('last_update', ?, CURRENT_TIMESTAMP)
            """, (datetime.now().isoformat(),))
            conn.commit()

    def close(self) -> None:
        """Close database connection and NVD client."""
        if self.nvd_client:
            self.nvd_client.close()
