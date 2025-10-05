"""NVD (National Vulnerability Database) REST API client with rate limiting."""
import os
import time
import logging
import requests
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class RateLimiter:
    """Rate limiter for NVD API requests."""

    requests_per_interval: int = 5  # Default: 5 requests per 30 seconds without API key
    interval_seconds: int = 30

    # Internal state
    _request_times: List[float] = field(default_factory=list, init=False)

    def wait_if_needed(self) -> None:
        """Wait if necessary to comply with rate limits."""
        current_time = time.time()

        # Remove requests older than the interval
        cutoff_time = current_time - self.interval_seconds
        self._request_times = [t for t in self._request_times if t > cutoff_time]

        # If at limit, wait until oldest request expires
        if len(self._request_times) >= self.requests_per_interval:
            oldest_request = self._request_times[0]
            wait_time = oldest_request + self.interval_seconds - current_time
            if wait_time > 0:
                logger.info(f"Rate limit reached, waiting {wait_time:.2f} seconds...")
                time.sleep(wait_time)
                # Clean up again after waiting
                current_time = time.time()
                cutoff_time = current_time - self.interval_seconds
                self._request_times = [t for t in self._request_times if t > cutoff_time]

        # Record this request
        self._request_times.append(current_time)


@dataclass
class CVEItem:
    """Represents a CVE vulnerability."""

    cve_id: str
    published_date: str
    last_modified_date: str
    description: str
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    affected_products: List[Dict[str, Any]] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)

    # Raw data for debugging/advanced use
    raw_data: Optional[Dict] = None


class NVDClient:
    """Client for interacting with the NVD REST API."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None, cache_dir: Optional[str] = None):
        """
        Initialize NVD API client.

        Args:
            api_key: NVD API key (optional, increases rate limits from 5 to 50 req/30s)
            cache_dir: Directory for caching CVE data (default: ~/.threat_radar/cache)
        """
        self.api_key = api_key or os.getenv("NVD_API_KEY")

        # Configure rate limiting based on API key presence
        if self.api_key:
            self.rate_limiter = RateLimiter(requests_per_interval=50, interval_seconds=30)
            logger.info("NVD API key configured - using enhanced rate limits (50 req/30s)")
        else:
            self.rate_limiter = RateLimiter(requests_per_interval=5, interval_seconds=30)
            logger.warning("No NVD API key - using public rate limits (5 req/30s)")

        # Setup cache directory
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            self.cache_dir = Path.home() / ".threat_radar" / "cache"

        self.cache_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Cache directory: {self.cache_dir}")

        # Session for connection pooling
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})

    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """
        Make a rate-limited request to the NVD API.

        Args:
            endpoint: API endpoint path
            params: Query parameters

        Returns:
            Response JSON data

        Raises:
            requests.HTTPError: On API errors
            requests.RequestException: On connection errors
        """
        # Apply rate limiting
        self.rate_limiter.wait_if_needed()

        url = f"{self.BASE_URL}"
        if endpoint:
            url = f"{url}/{endpoint}"

        try:
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response.json()

        except requests.HTTPError as e:
            if e.response.status_code == 403:
                logger.error("API key invalid or rate limit exceeded")
            elif e.response.status_code == 404:
                logger.error(f"Endpoint not found: {url}")
            else:
                logger.error(f"HTTP error: {e}")
            raise

        except requests.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise

    def get_cve_by_id(self, cve_id: str, use_cache: bool = True) -> Optional[CVEItem]:
        """
        Retrieve a specific CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2021-44228")
            use_cache: Whether to use cached data if available

        Returns:
            CVEItem object or None if not found
        """
        # Check cache first
        if use_cache:
            cached = self._get_from_cache(cve_id)
            if cached:
                logger.info(f"Retrieved {cve_id} from cache")
                return cached

        logger.info(f"Fetching {cve_id} from NVD API...")

        try:
            params = {"cveId": cve_id}
            response = self._make_request("", params)

            vulnerabilities = response.get("vulnerabilities", [])
            if not vulnerabilities:
                logger.warning(f"CVE {cve_id} not found")
                return None

            cve_item = self._parse_cve(vulnerabilities[0])

            # Cache the result
            self._save_to_cache(cve_item)

            return cve_item

        except requests.RequestException as e:
            logger.error(f"Failed to fetch {cve_id}: {e}")
            return None

    def search_cves(
        self,
        keyword: Optional[str] = None,
        cpe_name: Optional[str] = None,
        cvss_severity: Optional[str] = None,
        last_mod_start_date: Optional[datetime] = None,
        last_mod_end_date: Optional[datetime] = None,
        pub_start_date: Optional[datetime] = None,
        pub_end_date: Optional[datetime] = None,
        results_per_page: int = 100,
        start_index: int = 0
    ) -> List[CVEItem]:
        """
        Search for CVEs with various filters.

        Args:
            keyword: Keyword search (searches descriptions)
            cpe_name: CPE name to search for (e.g., "cpe:2.3:a:apache:log4j:2.14.1")
            cvss_severity: Filter by CVSS severity (LOW, MEDIUM, HIGH, CRITICAL)
            last_mod_start_date: Filter CVEs modified after this date
            last_mod_end_date: Filter CVEs modified before this date
            pub_start_date: Filter CVEs published after this date
            pub_end_date: Filter CVEs published before this date
            results_per_page: Number of results per page (max 2000)
            start_index: Starting index for pagination

        Returns:
            List of CVEItem objects
        """
        params: Dict[str, Any] = {
            "resultsPerPage": min(results_per_page, 2000),
            "startIndex": start_index
        }

        if keyword:
            params["keywordSearch"] = keyword

        if cpe_name:
            params["cpeName"] = cpe_name

        if cvss_severity:
            params["cvssV3Severity"] = cvss_severity.upper()

        if last_mod_start_date:
            params["lastModStartDate"] = last_mod_start_date.isoformat()

        if last_mod_end_date:
            params["lastModEndDate"] = last_mod_end_date.isoformat()

        if pub_start_date:
            params["pubStartDate"] = pub_start_date.isoformat()

        if pub_end_date:
            params["pubEndDate"] = pub_end_date.isoformat()

        logger.info(f"Searching CVEs with params: {params}")

        try:
            response = self._make_request("", params)
            vulnerabilities = response.get("vulnerabilities", [])

            cve_items = [self._parse_cve(vuln) for vuln in vulnerabilities]

            # Cache results
            for item in cve_items:
                self._save_to_cache(item)

            logger.info(f"Found {len(cve_items)} CVEs")
            return cve_items

        except requests.RequestException as e:
            logger.error(f"Search failed: {e}")
            return []

    def get_recent_cves(self, days: int = 7) -> List[CVEItem]:
        """
        Get CVEs modified in the last N days.

        Args:
            days: Number of days to look back

        Returns:
            List of CVEItem objects
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)

        logger.info(f"Fetching CVEs modified in last {days} days")
        return self.search_cves(
            last_mod_start_date=start_date,
            last_mod_end_date=end_date
        )

    def _parse_cve(self, vulnerability_data: Dict) -> CVEItem:
        """Parse NVD API response into CVEItem object."""
        cve = vulnerability_data.get("cve", {})

        # Extract basic info
        cve_id = cve.get("id", "")
        published = cve.get("published", "")
        last_modified = cve.get("lastModified", "")

        # Extract description
        descriptions = cve.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Extract CVSS metrics
        severity = None
        cvss_score = None
        cvss_vector = None

        metrics = cve.get("metrics", {})

        # Try CVSS v3.1 first, then v3.0, then v2.0
        for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if version in metrics and metrics[version]:
                metric_data = metrics[version][0]
                cvss_data = metric_data.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_vector = cvss_data.get("vectorString")
                severity = metric_data.get("baseSeverity") or cvss_data.get("baseSeverity")
                break

        # Extract affected products (CPE data)
        affected_products = []
        configurations = cve.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        product_info = {
                            "cpe23Uri": cpe_match.get("criteria"),
                            "versionStartIncluding": cpe_match.get("versionStartIncluding"),
                            "versionStartExcluding": cpe_match.get("versionStartExcluding"),
                            "versionEndIncluding": cpe_match.get("versionEndIncluding"),
                            "versionEndExcluding": cpe_match.get("versionEndExcluding"),
                        }
                        affected_products.append(product_info)

        # Extract references
        references = []
        for ref in cve.get("references", []):
            if "url" in ref:
                references.append(ref["url"])

        # Extract CWE IDs
        cwe_ids = []
        weaknesses = cve.get("weaknesses", [])
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    cwe_id = desc.get("value", "")
                    if cwe_id.startswith("CWE-"):
                        cwe_ids.append(cwe_id)

        return CVEItem(
            cve_id=cve_id,
            published_date=published,
            last_modified_date=last_modified,
            description=description,
            severity=severity,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            affected_products=affected_products,
            references=references,
            cwe_ids=cwe_ids,
            raw_data=vulnerability_data
        )

    def _get_cache_path(self, cve_id: str) -> Path:
        """Get cache file path for a CVE ID."""
        # Organize by year: CVE-2021-1234 -> 2021/CVE-2021-1234.json
        parts = cve_id.split("-")
        if len(parts) >= 2:
            year = parts[1]
            year_dir = self.cache_dir / year
            year_dir.mkdir(exist_ok=True)
            return year_dir / f"{cve_id}.json"
        return self.cache_dir / f"{cve_id}.json"

    def _get_from_cache(self, cve_id: str) -> Optional[CVEItem]:
        """Retrieve CVE from cache."""
        cache_path = self._get_cache_path(cve_id)

        if not cache_path.exists():
            return None

        try:
            import json
            with open(cache_path, 'r') as f:
                data = json.load(f)

            # Check if cache is stale (older than 7 days)
            cache_age = time.time() - cache_path.stat().st_mtime
            if cache_age > 7 * 24 * 3600:  # 7 days in seconds
                logger.info(f"Cache for {cve_id} is stale (age: {cache_age/86400:.1f} days)")
                return None

            return CVEItem(**data)

        except (json.JSONDecodeError, TypeError, KeyError) as e:
            logger.warning(f"Failed to load cache for {cve_id}: {e}")
            return None

    def _save_to_cache(self, cve_item: CVEItem) -> None:
        """Save CVE to cache."""
        cache_path = self._get_cache_path(cve_item.cve_id)

        try:
            import json
            from dataclasses import asdict

            # Don't cache raw_data to save space
            data = asdict(cve_item)
            data.pop("raw_data", None)

            with open(cache_path, 'w') as f:
                json.dump(data, f, indent=2)

            logger.debug(f"Cached {cve_item.cve_id}")

        except Exception as e:
            logger.warning(f"Failed to cache {cve_item.cve_id}: {e}")

    def clear_cache(self, older_than_days: Optional[int] = None) -> int:
        """
        Clear cached CVE data.

        Args:
            older_than_days: Only clear cache older than N days (None = clear all)

        Returns:
            Number of files removed
        """
        removed = 0
        cutoff_time = None

        if older_than_days:
            cutoff_time = time.time() - (older_than_days * 24 * 3600)

        for cache_file in self.cache_dir.rglob("*.json"):
            if cutoff_time is None or cache_file.stat().st_mtime < cutoff_time:
                cache_file.unlink()
                removed += 1

        logger.info(f"Removed {removed} cached files")
        return removed

    def close(self) -> None:
        """Close the HTTP session."""
        self.session.close()
