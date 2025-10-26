"""CVE scan storage management and retrieval."""
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import json
from collections import defaultdict
import re


@dataclass
class CVEScanMetadata:
    """Metadata for a stored CVE scan."""

    file_path: Path
    filename: str
    target: str
    scan_type: str  # image, sbom, directory
    total_vulnerabilities: int
    severity_counts: Dict[str, int]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    scan_date: datetime
    file_size: int
    file_size_str: str

    @property
    def critical_high_count(self) -> int:
        """Combined critical and high severity count."""
        return self.critical_count + self.high_count


@dataclass
class CVESearchResult:
    """Result from searching CVE scans."""

    scan_metadata: CVEScanMetadata
    matching_vulnerabilities: List[Dict[str, Any]]
    total_matches: int


@dataclass
class CVEAggregateStats:
    """Aggregate statistics across multiple CVE scans."""

    total_scans: int
    total_storage_size: int
    total_vulnerabilities: int
    unique_cve_ids: int
    severity_breakdown: Dict[str, int]
    top_cves: List[Tuple[str, int, int]]  # (cve_id, scan_count, package_count)
    package_type_breakdown: Dict[str, int]
    fix_availability: Dict[str, int]  # {fixed: count, no_fix: count}


class CVEStorageManager:
    """Manages CVE scan storage and retrieval operations."""

    def __init__(self, storage_dir: Optional[Path] = None):
        """Initialize CVE storage manager.

        Args:
            storage_dir: Path to CVE storage directory (default: ./storage/cve_storage/)
        """
        if storage_dir is None:
            storage_dir = Path("./storage/cve_storage")

        self.storage_dir = Path(storage_dir)

        # Create storage directory if it doesn't exist
        if not self.storage_dir.exists():
            self.storage_dir.mkdir(parents=True, exist_ok=True)

    def list_scans(
        self,
        type_filter: str = "all",
        severity_filter: Optional[str] = None,
        limit: Optional[int] = None,
        sort_by: str = "date"
    ) -> List[CVEScanMetadata]:
        """List all stored CVE scans with optional filtering.

        Args:
            type_filter: Filter by scan type (image, sbom, directory, all)
            severity_filter: Filter scans with minimum severity (critical, high, medium, low)
            limit: Maximum number of results to return
            sort_by: Sort field (date, vulnerabilities, critical, name)

        Returns:
            List of CVE scan metadata objects
        """
        scan_files = sorted(self.storage_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)

        scans = []
        for scan_file in scan_files:
            try:
                metadata = self.get_scan_metadata(scan_file)

                # Apply type filter
                if type_filter != "all" and metadata.scan_type != type_filter:
                    continue

                # Apply severity filter
                if severity_filter:
                    if not self._meets_severity_threshold(metadata.severity_counts, severity_filter):
                        continue

                scans.append(metadata)

            except Exception as e:
                # Skip invalid files
                continue

        # Sort scans
        scans = self._sort_scans(scans, sort_by)

        # Apply limit
        if limit:
            scans = scans[:limit]

        return scans

    def get_scan_metadata(self, scan_path: Path) -> CVEScanMetadata:
        """Extract metadata from a CVE scan file.

        Args:
            scan_path: Path to CVE scan JSON file

        Returns:
            CVEScanMetadata object
        """
        with open(scan_path, 'r') as f:
            data = json.load(f)

        # Determine scan type from data structure
        scan_type = "unknown"
        if "target" in data:
            scan_type = "image"
        elif "sbom_file" in data:
            scan_type = "sbom"
        elif "directory" in data:
            scan_type = "directory"

        # Extract target name
        target = data.get("target") or data.get("sbom_file") or data.get("directory", "unknown")

        # Get severity counts
        severity_counts = data.get("severity_counts", {})

        # Parse scan date from scan_metadata or file timestamp
        scan_date = None
        if "scan_metadata" in data and "descriptor" in data["scan_metadata"]:
            timestamp_str = data["scan_metadata"]["descriptor"].get("timestamp")
            if timestamp_str:
                try:
                    # Parse ISO format with timezone
                    scan_date = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                except:
                    pass

        if scan_date is None:
            # Fallback to file modification time
            scan_date = datetime.fromtimestamp(scan_path.stat().st_mtime)

        # Get file size
        file_size = scan_path.stat().st_size
        file_size_str = self._format_file_size(file_size)

        return CVEScanMetadata(
            file_path=scan_path,
            filename=scan_path.name,
            target=target,
            scan_type=scan_type,
            total_vulnerabilities=data.get("total_vulnerabilities", 0),
            severity_counts=severity_counts,
            critical_count=severity_counts.get("critical", 0),
            high_count=severity_counts.get("high", 0),
            medium_count=severity_counts.get("medium", 0),
            low_count=severity_counts.get("low", 0) + severity_counts.get("negligible", 0),
            scan_date=scan_date,
            file_size=file_size,
            file_size_str=file_size_str,
        )

    def load_scan(self, scan_path: Path) -> Dict[str, Any]:
        """Load full CVE scan data from file.

        Args:
            scan_path: Path to CVE scan JSON file

        Returns:
            Full scan data dictionary
        """
        with open(scan_path, 'r') as f:
            return json.load(f)

    def search_scans(
        self,
        query: str,
        query_type: str = "auto",
        severity_filter: Optional[str] = None,
        scan_pattern: str = "*",
        case_sensitive: bool = False,
        exact_match: bool = False
    ) -> List[CVESearchResult]:
        """Search across all CVE scans for matching vulnerabilities.

        Args:
            query: Search query string
            query_type: Type of search (auto, cve-id, package, description)
            severity_filter: Filter by minimum severity
            scan_pattern: Glob pattern to filter scans
            case_sensitive: Case-sensitive search
            exact_match: Exact match only (no partial matches)

        Returns:
            List of search results with matching vulnerabilities
        """
        # Get matching scan files
        scan_files = list(self.storage_dir.glob(f"{scan_pattern}.json"))

        results = []

        for scan_file in scan_files:
            try:
                metadata = self.get_scan_metadata(scan_file)
                data = self.load_scan(scan_file)

                # Search vulnerabilities
                matching_vulns = self._search_vulnerabilities(
                    data.get("vulnerabilities", []),
                    query,
                    query_type,
                    severity_filter,
                    case_sensitive,
                    exact_match
                )

                if matching_vulns:
                    results.append(CVESearchResult(
                        scan_metadata=metadata,
                        matching_vulnerabilities=matching_vulns,
                        total_matches=len(matching_vulns)
                    ))

            except Exception:
                continue

        return results

    def get_aggregate_stats(
        self,
        scan_pattern: str = "*",
        type_filter: str = "all"
    ) -> CVEAggregateStats:
        """Calculate aggregate statistics across stored CVE scans.

        Args:
            scan_pattern: Glob pattern to filter scans
            type_filter: Filter by scan type

        Returns:
            CVEAggregateStats object with aggregate data
        """
        scans = self.list_scans(type_filter=type_filter)

        if scan_pattern != "*":
            scans = [s for s in scans if s.file_path.match(scan_pattern)]

        total_vulnerabilities = 0
        total_storage_size = 0
        severity_breakdown = defaultdict(int)
        cve_occurrences = defaultdict(lambda: {"scan_count": 0, "package_count": 0})
        package_type_breakdown = defaultdict(int)
        fix_counts = {"fixed": 0, "no_fix": 0}

        for scan in scans:
            total_storage_size += scan.file_size
            total_vulnerabilities += scan.total_vulnerabilities

            # Aggregate severity counts
            for severity, count in scan.severity_counts.items():
                severity_breakdown[severity] += count

            # Load full scan for detailed analysis
            try:
                data = self.load_scan(scan.file_path)
                vulnerabilities = data.get("vulnerabilities", [])

                # Track unique CVEs
                seen_cves_in_scan = set()

                for vuln in vulnerabilities:
                    cve_id = vuln.get("id")
                    package_type = vuln.get("package_type", "unknown")
                    fixed_in = vuln.get("fixed_in")

                    # Count CVE occurrences
                    if cve_id:
                        cve_occurrences[cve_id]["package_count"] += 1
                        if cve_id not in seen_cves_in_scan:
                            cve_occurrences[cve_id]["scan_count"] += 1
                            seen_cves_in_scan.add(cve_id)

                    # Count package types
                    package_type_breakdown[package_type] += 1

                    # Count fix availability
                    if fixed_in:
                        fix_counts["fixed"] += 1
                    else:
                        fix_counts["no_fix"] += 1

            except Exception:
                continue

        # Get top CVEs
        top_cves = sorted(
            [(cve_id, data["scan_count"], data["package_count"])
             for cve_id, data in cve_occurrences.items()],
            key=lambda x: (x[1], x[2]),
            reverse=True
        )[:10]

        return CVEAggregateStats(
            total_scans=len(scans),
            total_storage_size=total_storage_size,
            total_vulnerabilities=total_vulnerabilities,
            unique_cve_ids=len(cve_occurrences),
            severity_breakdown=dict(severity_breakdown),
            top_cves=top_cves,
            package_type_breakdown=dict(sorted(
                package_type_breakdown.items(),
                key=lambda x: x[1],
                reverse=True
            )),
            fix_availability=fix_counts,
        )

    def _search_vulnerabilities(
        self,
        vulnerabilities: List[Dict[str, Any]],
        query: str,
        query_type: str,
        severity_filter: Optional[str],
        case_sensitive: bool,
        exact_match: bool
    ) -> List[Dict[str, Any]]:
        """Search vulnerabilities for matching entries."""
        matches = []

        # Auto-detect query type if needed
        if query_type == "auto":
            if query.upper().startswith("CVE-"):
                query_type = "cve-id"
            else:
                query_type = "package"

        for vuln in vulnerabilities:
            # Apply severity filter
            if severity_filter:
                vuln_severity = vuln.get("severity", "").lower()
                if not self._severity_meets_threshold(vuln_severity, severity_filter):
                    continue

            # Check if vulnerability matches query
            if self._matches_query(vuln, query, query_type, case_sensitive, exact_match):
                matches.append(vuln)

        return matches

    def _matches_query(
        self,
        vuln: Dict[str, Any],
        query: str,
        query_type: str,
        case_sensitive: bool,
        exact_match: bool
    ) -> bool:
        """Check if vulnerability matches search query."""
        if not case_sensitive:
            query = query.lower()

        if query_type == "cve-id":
            cve_id = vuln.get("id", "")
            if not case_sensitive:
                cve_id = cve_id.lower()

            if exact_match:
                return cve_id == query
            else:
                return query in cve_id

        elif query_type == "package":
            package = vuln.get("package", "")
            if not case_sensitive:
                package = package.lower()

            if exact_match:
                # Extract package name (before @)
                package_name = package.split("@")[0]
                return package_name == query
            else:
                return query in package

        elif query_type == "description":
            description = vuln.get("description", "")
            if not case_sensitive:
                description = description.lower()

            if exact_match:
                return query == description
            else:
                return query in description

        return False

    def _meets_severity_threshold(
        self,
        severity_counts: Dict[str, int],
        min_severity: str
    ) -> bool:
        """Check if scan has vulnerabilities meeting severity threshold."""
        severity_order = ["critical", "high", "medium", "low", "negligible"]
        min_level = severity_order.index(min_severity.lower())

        for i in range(min_level + 1):
            severity = severity_order[i]
            if severity_counts.get(severity, 0) > 0:
                return True

        return False

    def _severity_meets_threshold(self, vuln_severity: str, min_severity: str) -> bool:
        """Check if vulnerability severity meets minimum threshold."""
        severity_order = ["critical", "high", "medium", "low", "negligible", "unknown"]

        try:
            vuln_level = severity_order.index(vuln_severity)
            min_level = severity_order.index(min_severity.lower())
            return vuln_level <= min_level
        except ValueError:
            return False

    def _sort_scans(
        self,
        scans: List[CVEScanMetadata],
        sort_by: str
    ) -> List[CVEScanMetadata]:
        """Sort scans by specified field."""
        if sort_by == "date":
            return sorted(scans, key=lambda s: s.scan_date, reverse=True)
        elif sort_by == "vulnerabilities":
            return sorted(scans, key=lambda s: s.total_vulnerabilities, reverse=True)
        elif sort_by == "critical":
            return sorted(scans, key=lambda s: s.critical_high_count, reverse=True)
        elif sort_by == "name":
            return sorted(scans, key=lambda s: s.target)
        else:
            return scans

    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f}{unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f}TB"
