# Design Patterns in Threat Radar - Code Snippets for Live Demo

## 1. FACTORY PATTERN - Package Extractor Factory

### Problem
Different Linux distributions use different package managers:
- Debian/Ubuntu use `dpkg`
- Alpine uses `apk`
- RHEL/CentOS use `rpm`

Each has different output format and command to list packages.

### Solution: Factory Pattern

**File:** `threat_radar/core/package_extractors.py`

```python
# Step 1: Define common interface
class PackageExtractor:
    """Base class for package extractors."""
    def parse_packages(self, output: bytes) -> List[Package]:
        raise NotImplementedError

# Step 2: Create concrete implementations
class APTExtractor(PackageExtractor):
    """Extract packages from Debian/Ubuntu systems using dpkg."""
    @staticmethod
    def get_command() -> str:
        return "dpkg-query -W -f='${Package}|${Version}|${Architecture}|${Description}\\n'"
    
    def parse_packages(self, output: bytes) -> List[Package]:
        packages = []
        lines = output.decode('utf-8', errors='ignore').strip().split('\n')
        for line in lines:
            if not line.strip():
                continue
            parts = line.split('|', maxsplit=3)
            if len(parts) >= 2:
                package = Package(
                    name=parts[0].strip(),
                    version=parts[1].strip(),
                    architecture=parts[2].strip() if len(parts) > 2 else None,
                )
                packages.append(package)
        return packages

class APKExtractor(PackageExtractor):
    """Extract packages from Alpine Linux using apk."""
    @staticmethod
    def get_command() -> str:
        return "apk info -v"
    
    def parse_packages(self, output: bytes) -> List[Package]:
        packages = []
        pattern = re.compile(r'^(.+?)-(\d+[\.\d]*-r\d+)$')
        for line in output.decode('utf-8', errors='ignore').strip().split('\n'):
            match = pattern.match(line.strip())
            if match:
                packages.append(Package(
                    name=match.group(1),
                    version=match.group(2)
                ))
        return packages

# Step 3: Create factory
class PackageExtractorFactory:
    """Factory to get appropriate package extractor based on distro."""
    _extractors = {
        'debian': APTExtractor,
        'ubuntu': APTExtractor,
        'alpine': APKExtractor,
        'rhel': YUMExtractor,
        'centos': YUMExtractor,
        'fedora': YUMExtractor,
    }
    
    @classmethod
    def get_extractor(cls, distro: str) -> Optional[PackageExtractor]:
        """Get package extractor for given distribution."""
        distro_lower = distro.lower()
        extractor_class = cls._extractors.get(distro_lower)
        if extractor_class:
            return extractor_class()
        return None

# Step 4: Usage in client code
def analyze_container(image_name: str):
    distro = detect_distro(image_name)  # Returns 'ubuntu', 'alpine', etc.
    
    # Factory creates appropriate extractor
    extractor = PackageExtractorFactory.get_extractor(distro)
    
    if extractor:
        # Get command for this distro
        command = extractor.get_command()
        
        # Run command in container
        output = docker_client.run_container(image_name, command)
        
        # Parse using appropriate strategy
        packages = extractor.parse_packages(output)
        return packages

# Key Insight:
# - New distro support = just add new Extractor class + register in factory
# - No changes to client code
# - Easy to test each extractor independently
```

**Learning Points:**
1. Factory decouples client code from concrete implementations
2. Registry pattern (dictionary) maps names to classes
3. All implementations share common interface
4. Easy to extend without modifying existing code (Open/Closed Principle)

---

## 2. STRATEGY PATTERN - Report Formatters

### Problem
Reports need to be output in multiple formats:
- JSON (for automation)
- Markdown (for GitHub issues)
- HTML (for web browser)

### Solution: Strategy Pattern

**File:** `threat_radar/utils/report_formatters.py`

```python
# Step 1: Define strategy interface
class ReportFormatter:
    """Base class for report formatters."""
    def format(self, report: ComprehensiveReport) -> str:
        raise NotImplementedError

# Step 2: Implement concrete strategies
class JSONFormatter(ReportFormatter):
    """JSON format output."""
    def format(self, report: ComprehensiveReport, indent: int = 2) -> str:
        return json.dumps(report.to_dict(), indent=indent, default=str)

class MarkdownFormatter(ReportFormatter):
    """Markdown format output for documentation."""
    def format(self, report: ComprehensiveReport) -> str:
        md = []
        md.append(f"# Vulnerability Scan Report")
        md.append(f"**Report ID:** `{report.report_id}`")
        md.append(f"**Generated:** {report.generated_at}")
        md.append(f"**Target:** `{report.target}`")
        
        # Summary section
        md.append("## Summary Statistics")
        md.append(f"Total Vulnerabilities: {report.summary.total_vulnerabilities}")
        md.append(f"Critical: {report.summary.critical}")
        md.append(f"High: {report.summary.high}")
        
        # Findings section
        md.append("## Vulnerabilities")
        for finding in report.findings:
            md.append(f"### {finding.cve_id}")
            md.append(f"Severity: {finding.severity}")
            md.append(f"Package: {finding.package_name}@{finding.package_version}")
        
        return "\n".join(md)

class HTMLFormatter(ReportFormatter):
    """HTML format output."""
    def format(self, report: ComprehensiveReport) -> str:
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html>")
        html.append("<head>")
        html.append(f"<title>Vulnerability Report {report.report_id}</title>")
        html.append("<style>body { font-family: Arial; }</style>")
        html.append("</head>")
        html.append("<body>")
        
        html.append(f"<h1>Vulnerability Report</h1>")
        html.append(f"<p>Target: {report.target}</p>")
        
        # Severity distribution chart
        html.append("<h2>Severity Distribution</h2>")
        html.append(f"<ul>")
        html.append(f"<li>Critical: {report.summary.critical}</li>")
        html.append(f"<li>High: {report.summary.high}</li>")
        html.append(f"<li>Medium: {report.summary.medium}</li>")
        html.append(f"</ul>")
        
        # Findings table
        html.append("<h2>Findings</h2>")
        html.append("<table border='1'>")
        html.append("<tr><th>CVE</th><th>Package</th><th>Severity</th></tr>")
        for finding in report.findings:
            html.append(f"<tr><td>{finding.cve_id}</td><td>{finding.package_name}</td><td>{finding.severity}</td></tr>")
        html.append("</table>")
        
        html.append("</body>")
        html.append("</html>")
        return "\n".join(html)

# Step 3: Client code selects strategy
def save_report(report: ComprehensiveReport, output_file: str, format: str):
    # Strategy pattern: select formatter based on format
    formatters = {
        'json': JSONFormatter(),
        'markdown': MarkdownFormatter(),
        'html': HTMLFormatter(),
    }
    
    formatter = formatters.get(format.lower())
    if not formatter:
        raise ValueError(f"Unsupported format: {format}")
    
    # Format report using selected strategy
    output = formatter.format(report)
    
    # Save to file
    with open(output_file, 'w') as f:
        f.write(output)

# Usage:
report = generate_report(scan_result)
save_report(report, 'report.json', 'json')
save_report(report, 'report.md', 'markdown')
save_report(report, 'report.html', 'html')
```

**Learning Points:**
1. Strategy pattern eliminates if/else chains
2. Each algorithm (format) encapsulated in separate class
3. Easy to add new formats without changing existing code
4. At runtime, choose which strategy to use
5. Each strategy can be tested independently

---

## 3. ADAPTER PATTERN - Docker SDK Wrapper

### Problem
Docker Python SDK has complex error handling and connection management. We want:
- Simplified interface for our use case
- Consistent error translation
- Automatic logging
- Connection lifecycle management

### Solution: Adapter Pattern

**File:** `threat_radar/core/docker_integration.py`

```python
# External library (complex API)
import docker
from docker.errors import DockerException, ImageNotFound, APIError

# Adapter class
class DockerClient:
    """Wrapper for Docker SDK client with error handling."""
    
    def __init__(self):
        self._client: Optional[docker.DockerClient] = None
        self._connect()
    
    def _connect(self) -> None:
        """Establish connection to Docker daemon."""
        try:
            self._client = docker.from_env()
            # Verify connection
            self._client.ping()
            logger.info("Successfully connected to Docker daemon")
        except DockerException as e:
            logger.error(f"Failed to connect to Docker daemon: {e}")
            # Transform Docker exception to meaningful error
            raise ConnectionError(
                "Could not connect to Docker daemon. "
                "Ensure Docker is running and accessible."
            ) from e
    
    @property
    def client(self) -> docker.DockerClient:
        """Get the Docker client instance."""
        if self._client is None:
            raise ConnectionError("Docker client not initialized")
        return self._client
    
    def pull_image(self, image_name: str, tag: str = "latest") -> docker.models.images.Image:
        """
        Pull a Docker image from registry.
        
        Simplified interface hiding SDK complexity.
        """
        full_name = f"{image_name}:{tag}"
        try:
            logger.info(f"Pulling image: {full_name}")
            image = self.client.images.pull(image_name, tag=tag)
            logger.info(f"Successfully pulled image: {full_name}")
            return image
        except ImageNotFound as e:
            logger.error(f"Image not found: {full_name}")
            raise  # Re-raise but with context
        except APIError as e:
            logger.error(f"Failed to pull image {full_name}: {e}")
            raise
    
    def run_container(
        self,
        image_name: str,
        command: str,
        remove: bool = True,
        **kwargs
    ) -> bytes:
        """
        Run a command in a container and return output.
        
        Simplified interface for common use case.
        """
        try:
            logger.info(f"Running command in {image_name}: {command}")
            output = self.client.containers.run(
                image_name,
                command,
                remove=remove,
                **kwargs
            )
            return output
        except APIError as e:
            logger.error(f"Failed to run container: {e}")
            raise
    
    def inspect_image(self, image_name: str) -> dict:
        """Get detailed information about an image."""
        image = self.get_image(image_name)
        return image.attrs
    
    def close(self) -> None:
        """Close Docker client connection."""
        if self._client:
            self._client.close()
            logger.info("Docker client connection closed")

# Client code using adapter (much simpler!)
def analyze_container(image_name: str):
    # Use simplified adapter interface
    docker_client = DockerClient()
    
    try:
        # Pull image
        docker_client.pull_image("ubuntu", "22.04")
        
        # Inspect image
        info = docker_client.inspect_image("ubuntu:22.04")
        
        # Run command
        output = docker_client.run_container(
            "ubuntu:22.04",
            "dpkg-query -W -f='${Package}|${Version}\\n'",
            remove=True
        )
        
        return output
    finally:
        docker_client.close()  # Automatic cleanup
```

**Why This Pattern?**
1. **Simplified Interface:** Client code doesn't need to know Docker SDK complexity
2. **Error Translation:** Docker SDK errors → meaningful application errors
3. **Centralized Logging:** All Docker operations logged in one place
4. **Resource Management:** Connection lifecycle managed centrally
5. **Testability:** Easy to mock `DockerClient` for tests
6. **Future-proof:** If Docker API changes, only adapter needs updating

**Other Adapters in Codebase:**
- `GrypeClient` - wraps Grype CLI tool
- `SyftClient` - wraps Syft CLI tool
- `GitHubIntegration` - wraps PyGithub library

---

## 4. SINGLETON PATTERN - Global Configuration

### Problem
Application-wide configuration should:
- Be loaded once at startup
- Be accessible from anywhere
- Support multiple sources (file, env vars, defaults)
- Be resettable for testing

### Solution: Singleton Pattern

**File:** `threat_radar/utils/config_manager.py`

```python
# Configuration data model
@dataclass
class ScanDefaults:
    severity: Optional[str] = None
    only_fixed: bool = False
    auto_save: bool = False
    cleanup: bool = False

@dataclass
class AIDefaults:
    provider: Optional[str] = None
    model: Optional[str] = None
    temperature: float = 0.3

@dataclass
class ThreatRadarConfig:
    scan: ScanDefaults = field(default_factory=ScanDefaults)
    ai: AIDefaults = field(default_factory=AIDefaults)
    # ... more config sections

# Configuration manager class
class ConfigManager:
    DEFAULT_CONFIG_LOCATIONS = [
        Path.cwd() / ".threat-radar.json",
        Path.home() / ".threat-radar" / "config.json",
    ]
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path
        self.config = ThreatRadarConfig()  # Defaults
        self._load_config()
    
    def _load_config(self):
        """Load configuration from file."""
        config_file = self._find_config_file()
        if not config_file:
            return
        
        try:
            with open(config_file, 'r') as f:
                data = json.load(f)
            self.config = ThreatRadarConfig.from_dict(data)
            logger.info(f"Loaded configuration from: {config_file}")
        except Exception as e:
            logger.error(f"Error loading config: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get value by dot-notation key."""
        parts = key.split('.')
        value = self.config
        for part in parts:
            if hasattr(value, part):
                value = getattr(value, part)
            else:
                return default
        return value
    
    def set(self, key: str, value: Any):
        """Set value by dot-notation key."""
        parts = key.split('.')
        obj = self.config
        for part in parts[:-1]:
            if hasattr(obj, part):
                obj = getattr(obj, part)
        setattr(obj, parts[-1], value)

# SINGLETON IMPLEMENTATION
_config_manager: Optional[ConfigManager] = None

def get_config_manager(config_path: Optional[Path] = None) -> ConfigManager:
    """
    Get or create global configuration manager.
    
    This is the singleton accessor.
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager

def reset_config_manager():
    """Reset global configuration manager (useful for testing)."""
    global _config_manager
    _config_manager = None

# Usage anywhere in application
def scan_image_command(image: str):
    config_mgr = get_config_manager()  # Gets singleton instance
    
    # Access config via dot notation
    severity = config_mgr.get('scan.severity')
    auto_save = config_mgr.get('scan.auto_save')
    ai_provider = config_mgr.get('ai.provider')
    
    # No need to pass config through function parameters!
```

**Configuration Precedence (lowest to highest):**
```
Hardcoded defaults (in dataclasses)
    ↓
Configuration file (~/.threat-radar/config.json)
    ↓
Environment variables (THREAT_RADAR_SEVERITY)
    ↓
Command-line arguments (highest priority)
```

**Why Singleton?**
1. Single source of truth for configuration
2. Loaded once, accessed many times
3. Avoids passing config through every function
4. Reset method enables test isolation
5. Lazy initialization (created only when needed)

---

## 5. BUILDER PATTERN - Report Generation

### Problem
Generating comprehensive reports requires:
1. Parsing scan results
2. Grouping vulnerabilities by package
3. Computing statistics
4. Generating AI executive summary
5. Building dashboard data
6. Creating recommendations
7. Filtering based on level

This is complex and needs to be organized.

### Solution: Builder Pattern

**File:** `threat_radar/utils/comprehensive_report.py`

```python
class ComprehensiveReportGenerator:
    """Generate comprehensive vulnerability reports (Builder Pattern)."""
    
    def __init__(self, ai_provider: Optional[str] = None, ai_model: Optional[str] = None):
        self.ai_provider = ai_provider
        self.ai_model = ai_model
    
    def generate_report(
        self,
        scan_result: GrypeScanResult,
        report_level: ReportLevel = ReportLevel.DETAILED,
        include_executive_summary: bool = True,
        include_dashboard_data: bool = True,
    ) -> ComprehensiveReport:
        """
        Generate comprehensive vulnerability report.
        
        Builder builds complex object step-by-step.
        """
        
        logger.info(f"Generating {report_level.value} report for {scan_result.target}")
        
        # STEP 1: Create report ID and metadata
        report_id = f"vuln-report-{uuid.uuid4().hex[:8]}"
        
        # STEP 2: Build vulnerability findings
        findings = self._build_findings(scan_result)
        
        # STEP 3: Group vulnerabilities by package
        packages = self._build_package_groupings(findings)
        
        # STEP 4: Build summary statistics
        summary = self._build_summary(scan_result, findings)
        
        # STEP 5: Create base report with all components
        report = ComprehensiveReport(
            report_id=report_id,
            generated_at=datetime.now().isoformat(),
            report_level=report_level.value,
            target=scan_result.target,
            target_type=self._determine_target_type(scan_result),
            summary=summary,
            findings=findings,
            packages=packages,
            scan_metadata=scan_result.scan_metadata or {},
        )
        
        # STEP 6: (Optional) Add AI-powered executive summary
        if include_executive_summary and self.ai_provider:
            try:
                logger.info("Generating AI-powered executive summary...")
                report.executive_summary = self._generate_executive_summary(report)
            except Exception as e:
                logger.warning(f"Failed to generate executive summary: {e}")
        
        # STEP 7: (Optional) Add dashboard data for visualization
        if include_dashboard_data:
            logger.info("Generating dashboard visualization data...")
            report.dashboard_data = self._generate_dashboard_data(report)
        
        # STEP 8: Generate remediation recommendations
        report.remediation_recommendations = self._generate_remediation_recommendations(packages)
        
        # STEP 9: Apply report level filtering
        if report_level == ReportLevel.CRITICAL_ONLY:
            report = report.filter_critical_only()
        
        logger.info(f"Report generation complete: {report_id}")
        return report
    
    # Helper methods that build individual components
    def _build_findings(self, scan_result: GrypeScanResult) -> List[VulnerabilityFinding]:
        """Build vulnerability findings from scan result."""
        findings = []
        for vuln in scan_result.vulnerabilities:
            finding = VulnerabilityFinding(
                cve_id=vuln.id,
                severity=vuln.severity.lower(),
                cvss_score=vuln.cvss_score,
                package_name=vuln.package_name,
                package_version=vuln.package_version,
                package_type=vuln.package_type,
                fixed_in_version=vuln.fixed_in_version,
                description=vuln.description or "No description available",
                urls=vuln.urls or [],
            )
            findings.append(finding)
        return findings
    
    def _build_package_groupings(self, findings: List[VulnerabilityFinding]) -> List[PackageVulnerabilities]:
        """Group vulnerabilities by package."""
        package_map = defaultdict(list)
        
        for finding in findings:
            key = f"{finding.package_name}@{finding.package_version}"
            package_map[key].append(finding)
        
        packages = []
        for key, vulns in package_map.items():
            package_name, package_version = key.rsplit('@', 1)
            
            # Find highest severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            highest_severity = min(vulns, key=lambda v: severity_order.get(v.severity, 5)).severity
            
            packages.append(PackageVulnerabilities(
                package_name=package_name,
                package_version=package_version,
                vulnerability_count=len(vulns),
                highest_severity=highest_severity,
                vulnerabilities=vulns,
            ))
        
        return packages
    
    def _build_summary(self, scan_result: GrypeScanResult, findings: List[VulnerabilityFinding]) -> VulnerabilitySummary:
        """Build summary statistics."""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        cvss_scores = []
        
        for finding in findings:
            severity = finding.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            if finding.cvss_score:
                cvss_scores.append(finding.cvss_score)
        
        return VulnerabilitySummary(
            total_vulnerabilities=len(findings),
            critical=severity_counts['critical'],
            high=severity_counts['high'],
            medium=severity_counts['medium'],
            low=severity_counts['low'],
            vulnerable_packages=len(set(f.package_name for f in findings)),
            average_cvss_score=sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0,
            highest_cvss_score=max(cvss_scores) if cvss_scores else 0.0,
            vulnerabilities_with_fix=len([f for f in findings if f.fixed_in_version]),
            vulnerabilities_without_fix=len([f for f in findings if not f.fixed_in_version]),
        )

# Usage
generator = ComprehensiveReportGenerator(ai_provider='openai')
report = generator.generate_report(
    scan_result,
    report_level=ReportLevel.DETAILED,
    include_executive_summary=True,
    include_dashboard_data=True
)
```

**Key Characteristics:**
1. Each step encapsulated in separate method
2. Optional components added conditionally
3. Complex object assembled from simpler pieces
4. Easy to understand flow (step-by-step)
5. Easy to test individual steps
6. Easy to modify or reorder steps

---

## Summary Table: When to Use Each Pattern

| Pattern | Use Case | Example in Code |
|---------|----------|-----------------|
| **Factory** | Creating objects based on condition | `PackageExtractorFactory.get_extractor(distro)` |
| **Strategy** | Multiple algorithms for same task | Different `ReportFormatter` implementations |
| **Adapter** | Wrapping external libraries | `DockerClient` wraps Docker SDK |
| **Singleton** | Single global instance | `get_config_manager()` returns single instance |
| **Builder** | Complex object construction | `ComprehensiveReportGenerator.generate_report()` |

