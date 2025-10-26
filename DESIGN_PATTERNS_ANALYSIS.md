# Threat Radar Architecture & Design Patterns Analysis
## Executive Summary for Midterm Presentation

This document provides a detailed walkthrough of design patterns and architectural decisions in the Threat Radar vulnerability assessment platform. The analysis includes concrete code examples and file references suitable for an academic presentation.

---

## 1. DESIGN PATTERNS IDENTIFIED

### 1.1 FACTORY PATTERN

Factory patterns are extensively used to create instances of different implementations based on runtime configuration.

#### Pattern 1.1.1: PackageExtractorFactory (Strategy + Factory Hybrid)

**Location:** `/Users/chemch/PycharmProjects/tr-m2/threat_radar/core/package_extractors.py`

**Purpose:** Create appropriate package extractors for different Linux distributions

**Implementation Details:**

```python
# Base class with common interface
class PackageExtractor:
    def parse_packages(self, output: bytes) -> List[Package]:
        raise NotImplementedError

# Concrete implementations for different distros
class APTExtractor(PackageExtractor):    # Debian/Ubuntu
    def parse_packages(self, output: bytes) -> List[Package]:
        # dpkg output parsing logic
        
class APKExtractor(PackageExtractor):    # Alpine Linux
    def parse_packages(self, output: bytes) -> List[Package]:
        # apk output parsing logic
        
class YUMExtractor(PackageExtractor):    # RHEL/CentOS/Fedora
    def parse_packages(self, output: bytes) -> List[Package]:
        # rpm output parsing logic

# Factory class
class PackageExtractorFactory:
    _extractors = {
        'debian': APTExtractor,
        'ubuntu': APTExtractor,
        'alpine': APKExtractor,
        'rhel': YUMExtractor,
        'centos': YUMExtractor,
        'fedora': YUMExtractor,
        'rocky': YUMExtractor,
        'almalinux': YUMExtractor,
    }
    
    @classmethod
    def get_extractor(cls, distro: str) -> Optional[PackageExtractor]:
        """Get package extractor for given distribution"""
        distro_lower = distro.lower()
        extractor_class = cls._extractors.get(distro_lower)
        if extractor_class:
            return extractor_class()
        return None
```

**Educational Value:**
- Shows how to decouple client code from concrete implementations
- Maps distro names to specific extractors via a registry dictionary
- Each extractor implements same interface but handles distro-specific parsing
- Easy to add new distributions without modifying client code

---

#### Pattern 1.1.2: LLM Client Factory

**Location:** `/Users/chemch/PycharmProjects/tr-m2/threat_radar/ai/llm_client.py`

**Purpose:** Abstract creation of different AI provider clients

**Implementation Details:**

```python
# Abstract base class
class LLMClient(ABC):
    @abstractmethod
    def generate(self, prompt: str, temperature: float = 0.7) -> str:
        pass
    
    @abstractmethod
    def generate_json(self, prompt: str, temperature: float = 0.7) -> Dict:
        pass

# Concrete implementations
class OpenAIClient(LLMClient):
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4o"):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model
        self.client = OpenAI(api_key=self.api_key)
    
    def generate(self, prompt: str, temperature: float = 0.7) -> str:
        # OpenAI-specific implementation using Chat API

class AnthropicClient(LLMClient):
    def __init__(self, api_key: Optional[str] = None, model: str = "claude-3-5-sonnet-20241022"):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.model = model
        self.client = Anthropic(api_key=self.api_key)
    
    def generate(self, prompt: str, temperature: float = 0.7) -> str:
        # Anthropic-specific implementation

class OllamaClient(LLMClient):
    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama2"):
        self.base_url = base_url
        self.model = model
    
    def generate(self, prompt: str, temperature: float = 0.7) -> str:
        # Local Ollama implementation using REST API

# Factory function
def get_llm_client(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    endpoint: Optional[str] = None,
) -> LLMClient:
    """Factory function to get LLM client based on configuration"""
    provider = provider or os.getenv("AI_PROVIDER", "openai")
    model = model or os.getenv("AI_MODEL")
    
    if provider == "openai":
        return OpenAIClient(api_key=api_key, model=model or "gpt-4o")
    elif provider == "anthropic":
        return AnthropicClient(api_key=api_key, model=model or "claude-3-5-sonnet-20241022")
    elif provider == "ollama":
        default_endpoint = endpoint or os.getenv("LOCAL_MODEL_ENDPOINT", "http://localhost:11434")
        return OllamaClient(base_url=default_endpoint, model=model or "llama2")
    else:
        raise ValueError(f"Invalid AI provider: {provider}")
```

**Educational Value:**
- Factory function pattern using function dispatch (not class factory)
- Defers choice of concrete implementation to runtime
- Supports switching between cloud-based (OpenAI, Anthropic) and local (Ollama) models
- Configuration-driven via environment variables
- All implementations behind common LLMClient interface

---

### 1.2 STRATEGY PATTERN

The Strategy pattern allows selecting algorithms at runtime. Multiple implementations of an interface with different behaviors.

#### Pattern 1.2.1: Report Formatters (Strategy Pattern)

**Location:** `/Users/chemch/PycharmProjects/tr-m2/threat_radar/utils/report_formatters.py`

**Purpose:** Generate reports in multiple output formats (JSON, Markdown, HTML)

**Implementation:**

```python
# Base strategy interface
class ReportFormatter:
    """Base class for report formatters"""
    def format(self, report: ComprehensiveReport) -> str:
        raise NotImplementedError

# Concrete strategies
class JSONFormatter(ReportFormatter):
    """JSON format output"""
    def format(self, report: ComprehensiveReport, indent: int = 2) -> str:
        return json.dumps(report.to_dict(), indent=indent, default=str)

class MarkdownFormatter(ReportFormatter):
    """Markdown format output for documentation"""
    def format(self, report: ComprehensiveReport) -> str:
        md = []
        md.append(f"# Vulnerability Scan Report")
        md.append(f"**Report ID:** `{report.report_id}`")
        # ... Build markdown content
        return "\n".join(md)

class HTMLFormatter(ReportFormatter):
    """HTML format output"""
    def format(self, report: ComprehensiveReport) -> str:
        html = []
        html.append("<!DOCTYPE html>")
        html.append("<html>")
        # ... Build HTML content
        return "\n".join(html)

# Client code selecting strategy at runtime
def generate_report(report: ComprehensiveReport, format: str) -> str:
    formatters = {
        'json': JSONFormatter(),
        'markdown': MarkdownFormatter(),
        'html': HTMLFormatter(),
    }
    formatter = formatters.get(format.lower())
    if not formatter:
        raise ValueError(f"Unsupported format: {format}")
    return formatter.format(report)
```

**Educational Value:**
- Each formatter encapsulates a different algorithm for output generation
- Client code doesn't need to know implementation details
- Easy to add new formats without modifying existing code
- Runtime selection based on user input

---

#### Pattern 1.2.2: Package Extractors (Strategy + Template Method)

**Location:** `/Users/chemch/PycharmProjects/tr-m2/threat_radar/core/package_extractors.py`

Each extractor implements the same interface but with distro-specific parsing logic:

```python
class APTExtractor(PackageExtractor):
    @staticmethod
    def get_command() -> str:
        return "dpkg-query -W -f='${Package}|${Version}|${Architecture}|${Description}\\n'"
    
    def parse_packages(self, output: bytes) -> List[Package]:
        # APT/dpkg specific parsing strategy
        packages = []
        lines = output.decode('utf-8', errors='ignore').strip().split('\n')
        for line in lines:
            parts = line.split('|', maxsplit=3)
            # Parse 4-part format: name|version|arch|description
            ...

class APKExtractor(PackageExtractor):
    @staticmethod
    def get_command() -> str:
        return "apk info -v"
    
    def parse_packages(self, output: bytes) -> List[Package]:
        # APK specific parsing strategy
        packages = []
        pattern = re.compile(r'^(.+?)-(\d+[\.\d]*-r\d+)$')
        # Parse name-version-release format
        ...
```

**Educational Value:**
- Each distro manager requires different parsing strategy
- Same interface, different parsing algorithms per distro
- Demonstrates flexibility of strategy pattern

---

### 1.3 ADAPTER/WRAPPER PATTERN

Wrappers around external libraries to provide consistent interfaces and error handling.

#### Pattern 1.3.1: Docker SDK Adapter

**Location:** `/Users/chemch/PycharmProjects/tr-m2/threat_radar/core/docker_integration.py`

**Purpose:** Wrap Docker SDK with error handling and simplified interface

```python
class DockerClient:
    """Wrapper for Docker SDK client with error handling"""
    
    def __init__(self):
        self._client: Optional[docker.DockerClient] = None
        self._connect()
    
    def _connect(self) -> None:
        """Establish connection to Docker daemon"""
        try:
            self._client = docker.from_env()
            self._client.ping()
            logger.info("Successfully connected to Docker daemon")
        except DockerException as e:
            logger.error(f"Failed to connect to Docker daemon: {e}")
            raise ConnectionError(
                "Could not connect to Docker daemon. "
                "Ensure Docker is running and accessible."
            ) from e
    
    def pull_image(self, image_name: str, tag: str = "latest") -> docker.models.images.Image:
        """Pull a Docker image from registry"""
        full_name = f"{image_name}:{tag}"
        try:
            logger.info(f"Pulling image: {full_name}")
            image = self.client.images.pull(image_name, tag=tag)
            logger.info(f"Successfully pulled image: {full_name}")
            return image
        except ImageNotFound as e:
            logger.error(f"Image not found: {full_name}")
            raise
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
        """Run a command in a container and return output"""
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
```

**Key Features:**
1. **Connection Management:** Handles Docker daemon connection lifecycle
2. **Error Translation:** Converts Docker SDK exceptions to meaningful errors
3. **Simplified Interface:** Methods like `pull_image()` hide SDK complexity
4. **Logging:** Integrated logging for debugging
5. **Resource Cleanup:** Manages container removal via context managers

**Educational Value:**
- Shows how to wrap external libraries
- Provides consistent error handling
- Simplifies client code by hiding SDK complexity
- Enables easier testing through mock replacements

---

#### Pattern 1.3.2: External Tool Wrappers (CLI Adapters)

**Location:**
- `/Users/chemch/PycharmProjects/tr-m2/threat_radar/core/grype_integration.py`
- `/Users/chemch/PycharmProjects/tr-m2/threat_radar/core/syft_integration.py`

**Purpose:** Adapt external CLI tools (Grype, Syft) to Python API

```python
# Grype wrapper
class GrypeClient:
    """Client for interacting with Grype vulnerability scanner"""
    
    def __init__(self, grype_path: Optional[str] = None):
        self.grype_path = grype_path or "grype"
        self._check_installation()
    
    def _check_installation(self) -> None:
        """Verify Grype is installed and accessible"""
        try:
            result = subprocess.run(
                [self.grype_path, "version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                raise RuntimeError(f"Grype check failed: {result.stderr}")
            logger.info(f"Grype is available: {result.stdout.split()[0]}")
        except FileNotFoundError:
            raise RuntimeError(
                f"Grype not found at {self.grype_path}. "
                "Install it from: https://github.com/anchore/grype#installation"
            )
    
    def scan_docker_image(
        self,
        image_name: str,
        output_format: GrypeOutputFormat = GrypeOutputFormat.JSON,
        scope: str = "squashed",
        fail_on_severity: Optional[GrypeSeverity] = None
    ) -> GrypeScanResult:
        """Scan Docker image for vulnerabilities using Grype CLI"""
        # Build command with parameters
        cmd = [self.grype_path, f"docker:{image_name}", "-o", output_format.value]
        
        if scope:
            cmd.extend(["--scope", scope])
        
        if fail_on_severity:
            cmd.extend(["--fail-on", fail_on_severity.value])
        
        # Execute CLI command
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Parse JSON output into Python dataclass
        scan_data = json.loads(result.stdout)
        
        # Convert to GrypeScanResult
        return self._parse_grype_output(scan_data)
    
    def _parse_grype_output(self, data: Dict) -> GrypeScanResult:
        """Convert Grype JSON output to GrypeScanResult dataclass"""
        vulnerabilities = [
            GrypeVulnerability(
                id=v['vulnerability']['id'],
                severity=v['vulnerability']['severity'],
                package_name=v['artifact']['name'],
                # ... more mappings
            )
            for v in data.get('matches', [])
        ]
        
        return GrypeScanResult(
            target=data['source']['target'],
            vulnerabilities=vulnerabilities
        )

# Similar pattern for Syft
class SyftClient:
    """Wrapper for Syft CLI tool"""
    
    def __init__(self, syft_path: Optional[str] = None):
        self.syft_path = syft_path or "syft"
        self._check_installation()
    
    def scan(
        self,
        target: Union[str, Path],
        output_format: SBOMFormat = SBOMFormat.SYFT_JSON,
        scope: str = "all-layers",
        quiet: bool = False,
        additional_args: Optional[List[str]] = None
    ) -> Union[Dict, str]:
        """Scan target and generate SBOM"""
        cmd = [
            self.syft_path,
            "scan",
            str(target),
            "-o", output_format.value,
            "--scope", scope
        ]
        
        if quiet:
            cmd.append("--quiet")
        
        if additional_args:
            cmd.extend(additional_args)
        
        # Execute and parse output
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if output_format.value.endswith('json'):
            return json.loads(result.stdout)
        return result.stdout
```

**Educational Value:**
- Adapts CLI tools to Python API
- Handles version checking and error handling
- Parses CLI output into structured Python objects (dataclasses)
- Provides consistent interface regardless of underlying tool changes
- Enables testing through mocking

---

### 1.4 SINGLETON PATTERN

Global state management using singletons for configuration and context.

#### Pattern 1.4.1: Global Configuration Manager

**Location:** `/Users/chemch/PycharmProjects/tr-m2/threat_radar/utils/config_manager.py`

```python
# Singleton implementation using module-level global
_config_manager: Optional[ConfigManager] = None

def get_config_manager(config_path: Optional[Path] = None) -> ConfigManager:
    """Get or create global configuration manager"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager(config_path)
    return _config_manager

def reset_config_manager():
    """Reset global configuration manager (useful for testing)"""
    global _config_manager
    _config_manager = None
```

**Usage Pattern:**
```python
# Anywhere in codebase
config_mgr = get_config_manager()  # Gets existing instance or creates new one
severity = config_mgr.get('scan.severity')
```

**Educational Value:**
- Ensures single configuration instance across application
- Lazy initialization - created only when needed
- Reset method for testing
- Avoids passing config through multiple function calls

---

#### Pattern 1.4.2: Global CLI Context

**Location:** `/Users/chemch/PycharmProjects/tr-m2/threat_radar/utils/cli_context.py`

```python
@dataclass
class CLIContext:
    """Global CLI context holding configuration and state"""
    config_manager: ConfigManager
    verbosity: int
    output_format: str
    no_color: bool
    no_progress: bool
    console: Console
    
    @classmethod
    def create(
        cls,
        config_file: Optional[Path] = None,
        verbosity: int = 1,
        output_format: str = "table",
        no_color: bool = False,
        no_progress: bool = False,
    ) -> 'CLIContext':
        """Create CLI context with specified options"""
        config_manager = get_config_manager(config_file)
        # Apply verbosity from config if not explicitly set
        if verbosity == 1 and config_manager.get('output.verbosity'):
            verbosity = config_manager.get('output.verbosity')
        # ... more config handling
        return cls(...)

# Global context storage
_cli_context: Optional[CLIContext] = None

def get_cli_context() -> Optional[CLIContext]:
    """Get current CLI context"""
    return _cli_context

def set_cli_context(context: CLIContext):
    """Set global CLI context"""
    global _cli_context
    _cli_context = context

def reset_cli_context():
    """Reset CLI context (useful for testing)"""
    global _cli_context
    _cli_context = None
```

**Usage in Main App:**
```python
# threat_radar/cli/app.py
@app.callback()
def main_callback(
    config_file: Optional[Path] = None,
    verbosity: int = 1,
    quiet: bool = False,
    output_format: str = "table",
    no_color: bool = False,
    no_progress: bool = False,
):
    # Create and set global context
    context = CLIContext.create(
        config_file=config_file,
        verbosity=verbosity,
        output_format=output_format,
        no_color=no_color,
        no_progress=no_progress,
    )
    set_cli_context(context)

# Then any command can access it
def some_command():
    ctx = get_cli_context()
    console = ctx.console
    verbosity = ctx.verbosity
```

**Educational Value:**
- Manages global CLI state (verbosity, format, colors)
- Created once at startup via callback
- Accessible from any command without parameter passing
- Reset for testing

---

### 1.5 BUILDER PATTERN

Building complex objects with fluent interface or step-by-step construction.

#### Pattern 1.5.1: Report Construction

**Location:** `/Users/chemch/PycharmProjects/tr-m2/threat_radar/utils/comprehensive_report.py`

```python
class ComprehensiveReportGenerator:
    """Generate comprehensive vulnerability reports"""
    
    def generate_report(
        self,
        scan_result: GrypeScanResult,
        report_level: ReportLevel = ReportLevel.DETAILED,
        include_executive_summary: bool = True,
        include_dashboard_data: bool = True,
    ) -> ComprehensiveReport:
        """Generate report by building components step-by-step"""
        
        # Step 1: Create report ID and timestamp
        report_id = f"vuln-report-{uuid.uuid4().hex[:8]}"
        
        # Step 2: Build findings
        findings = self._build_findings(scan_result)
        
        # Step 3: Build package groupings
        packages = self._build_package_groupings(findings)
        
        # Step 4: Build summary statistics
        summary = self._build_summary(scan_result, findings)
        
        # Step 5: Create base report
        report = ComprehensiveReport(
            report_id=report_id,
            generated_at=datetime.now().isoformat(),
            report_level=report_level.value,
            target=scan_result.target,
            summary=summary,
            findings=findings,
            packages=packages,
        )
        
        # Step 6: Add executive summary if requested
        if include_executive_summary and self.ai_provider:
            try:
                report.executive_summary = self._generate_executive_summary(report)
            except Exception as e:
                logger.warning(f"Failed to generate executive summary: {e}")
        
        # Step 7: Add dashboard data if requested
        if include_dashboard_data:
            report.dashboard_data = self._generate_dashboard_data(report)
        
        # Step 8: Generate remediation recommendations
        report.remediation_recommendations = self._generate_remediation_recommendations(packages)
        
        # Step 9: Apply report level filtering
        if report_level == ReportLevel.CRITICAL_ONLY:
            report = report.filter_critical_only()
        
        return report
```

**Educational Value:**
- Complex object (ComprehensiveReport) built through multiple steps
- Each step encapsulated in its own method
- Optional components added conditionally
- Final filtering applied at end
- Shows how to decompose complex construction logic

---

### 1.6 DECORATOR PATTERN

Decorators and context managers for adding functionality.

#### Pattern 1.6.1: Context Managers for Cleanup

**Location:** `/Users/chemch/PycharmProjects/tr-m2/threat_radar/utils/docker_cleanup.py`

```python
# Not directly shown, but used in CLI commands
class ScanCleanupContext:
    """Context manager for Docker image cleanup after scanning"""
    
    def __init__(self, image_name: str, cleanup: bool = False):
        self.image_name = image_name
        self.cleanup = cleanup
        self.image_existed_before = False
    
    def __enter__(self):
        # Check if image exists before scan
        self.image_existed_before = self._image_exists(self.image_name)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Only cleanup if image was pulled during scan
        if self.cleanup and not self.image_existed_before:
            self._remove_image(self.image_name)

# Usage in CLI command
@app.command("scan-image")
def scan_docker_image(image: str, cleanup: bool = False):
    """Scan Docker image with automatic cleanup"""
    with ScanCleanupContext(image, cleanup=cleanup):
        # Perform scan
        pass
    # Image automatically cleaned up after context exit
```

**Educational Value:**
- Ensures cleanup happens regardless of success/failure
- Tracks image existence before scan
- Only removes images that were newly pulled
- Simplifies error handling

---

### 1.7 DATA CLASS / VALUE OBJECT PATTERN

Extensive use of dataclasses for data models and domain objects.

#### Pattern 1.7.1: Domain Models

**Location:** `/Users/chemch/PycharmProjects/tr-m2/threat_radar/core/package_extractors.py`

```python
@dataclass
class Package:
    """Represents an installed package"""
    name: str
    version: str
    architecture: Optional[str] = None
    description: Optional[str] = None
```

**Location:** `/Users/chemch/PycharmProjects/tr-m2/threat_radar/core/grype_integration.py`

```python
@dataclass
class GrypeVulnerability:
    """Represents a vulnerability found by Grype"""
    id: str  # CVE ID
    severity: str
    package_name: str
    package_version: str
    package_type: str
    fixed_in_version: Optional[str] = None
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    urls: List[str] = field(default_factory=list)
    data_source: Optional[str] = None
    namespace: Optional[str] = None
    artifact_path: Optional[str] = None
    artifact_location: Optional[str] = None

@dataclass
class GrypeScanResult:
    """Results of a Grype vulnerability scan"""
    target: str
    vulnerabilities: List[GrypeVulnerability] = field(default_factory=list)
    total_count: int = 0
    severity_counts: Dict[str, int] = field(default_factory=dict)
    scan_metadata: Optional[Dict] = None
    
    def __post_init__(self):
        """Calculate severity counts if not provided"""
        if not self.severity_counts and self.vulnerabilities:
            counts = {}
            for vuln in self.vulnerabilities:
                severity = vuln.severity.lower()
                counts[severity] = counts.get(severity, 0) + 1
            self.severity_counts = counts
        
        if not self.total_count:
            self.total_count = len(self.vulnerabilities)
    
    def filter_by_severity(self, min_severity: GrypeSeverity) -> 'GrypeScanResult':
        """Filter vulnerabilities by minimum severity"""
        severity_order = {
            GrypeSeverity.NEGLIGIBLE: 0,
            GrypeSeverity.LOW: 1,
            GrypeSeverity.MEDIUM: 2,
            GrypeSeverity.HIGH: 3,
            GrypeSeverity.CRITICAL: 4
        }
        
        min_level = severity_order[min_severity]
        
        filtered_vulns = [
            v for v in self.vulnerabilities
            if severity_order.get(GrypeSeverity(v.severity.lower()), 0) >= min_level
        ]
        
        return GrypeScanResult(
            target=self.target,
            vulnerabilities=filtered_vulns,
            scan_metadata=self.scan_metadata
        )
```

**Educational Value:**
- Type-safe domain models
- Post-initialization logic via `__post_init__`
- Methods on domain objects (filter_by_severity)
- Immutable-by-design (frozen=True optional)
- Serializable (can be converted to dict/JSON)

---

### 1.8 BRIDGE PATTERN

Separating abstraction from implementation.

#### Pattern 1.8.1: AI Provider Abstraction

**Location:** `/Users/chemch/PycharmProjects/tr-m2/threat_radar/ai/vulnerability_analyzer.py`

```python
class VulnerabilityAnalyzer:
    """Analyzes vulnerabilities using AI to provide context and insights"""
    
    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        provider: Optional[str] = None,
        model: Optional[str] = None,
        batch_size: int = 25,
        auto_batch_threshold: int = 30,
    ):
        # Bridge between high-level analyzer and low-level LLM implementations
        self.llm_client = llm_client or get_llm_client(provider=provider, model=model)
        self.batch_size = batch_size
        self.auto_batch_threshold = auto_batch_threshold
    
    def analyze_scan_result(
        self,
        scan_result: GrypeScanResult,
        temperature: float = 0.3,
        batch_mode: Optional[str] = "auto",
        progress_callback: Optional[Callable[[int, int, int], None]] = None,
    ) -> VulnerabilityAnalysis:
        """
        Analyze using abstracted LLM client - doesn't care about implementation
        """
        # Determine batching strategy
        use_batching = False
        if batch_mode == "enabled":
            use_batching = True
        elif batch_mode == "auto" and len(scan_result.vulnerabilities) > self.auto_batch_threshold:
            use_batching = True
        
        if use_batching:
            return self._analyze_with_batching(scan_result, temperature, progress_callback)
        else:
            return self._analyze_single_pass(scan_result, temperature)
    
    def _analyze_single_pass(
        self,
        scan_result: GrypeScanResult,
        temperature: float
    ) -> VulnerabilityAnalysis:
        """Single-pass analysis using abstracted LLM client"""
        prompt = create_analysis_prompt(scan_result.vulnerabilities)
        
        # Call abstracted interface - works with any LLMClient implementation
        response_json = self.llm_client.generate_json(prompt, temperature=temperature)
        
        # Process response...
        vulnerabilities = [
            VulnerabilityInsight(
                cve_id=item['cve_id'],
                package_name=item['package_name'],
                exploitability=item['exploitability'],
                # ... more fields
            )
            for item in response_json.get('vulnerabilities', [])
        ]
        
        return VulnerabilityAnalysis(
            vulnerabilities=vulnerabilities,
            summary=response_json.get('summary', ''),
            metadata={'provider': 'single-pass'}
        )
```

**Educational Value:**
- Abstraction (VulnerabilityAnalyzer) independent from implementation (OpenAI, Anthropic, Ollama)
- Can switch LLM providers without changing analyzer code
- Batch processing bridge between high-level analysis and low-level LLM calls

---

---

## 2. ARCHITECTURAL STRUCTURE

### 2.1 Layered Architecture

```
┌─────────────────────────────────────────────────┐
│  CLI Layer (threat_radar/cli/)                  │
│  - Commands: cve, sbom, ai, report, docker     │
│  - Typer-based argument parsing                │
│  - Global options callback                     │
└──────────────────────────────────────────────────┘
            ↓
┌─────────────────────────────────────────────────┐
│  Context & Configuration (utils/)               │
│  - CLIContext: Global state management          │
│  - ConfigManager: Configuration handling        │
│  - CLI utilities and helpers                    │
└──────────────────────────────────────────────────┘
            ↓
┌──────────────────────────────────────────────────┐
│  Domain & Integration Layer (core/, ai/)         │
│  ┌──────────────────────────────────────────┐   │
│  │ Docker Integration                       │   │
│  │ - DockerClient: SDK wrapper             │   │
│  │ - ContainerAnalyzer: Analysis           │   │
│  │ - PackageExtractors: Per-distro parsers │   │
│  └──────────────────────────────────────────┘   │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │ Vulnerability Scanning                   │   │
│  │ - GrypeClient: CLI wrapper for Grype    │   │
│  │ - GrypeScanResult: Domain model         │   │
│  │ - GrypeVulnerability: Domain model      │   │
│  └──────────────────────────────────────────┘   │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │ SBOM Generation                          │   │
│  │ - SyftClient: CLI wrapper for Syft      │   │
│  │ - SBOMFormat: Enum for formats          │   │
│  │ - SyftPackage: Domain model             │   │
│  └──────────────────────────────────────────┘   │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │ AI Analysis                              │   │
│  │ - LLMClient: Abstract base class         │   │
│  │ - OpenAIClient, AnthropicClient,         │   │
│  │   OllamaClient: Implementations          │   │
│  │ - VulnerabilityAnalyzer: Analysis engine│   │
│  │ - VulnerabilityInsight: Domain model    │   │
│  └──────────────────────────────────────────┘   │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │ Reporting                                │   │
│  │ - ComprehensiveReportGenerator: Builder  │   │
│  │ - ComprehensiveReport: Domain model      │   │
│  │ - ReportFormatter strategies             │   │
│  └──────────────────────────────────────────┘   │
│                                                  │
│  ┌──────────────────────────────────────────┐   │
│  │ GitHub Integration                       │   │
│  │ - GitHubIntegration: API wrapper         │   │
│  │ - Repository analysis and dependency     │   │
│  │   extraction                             │   │
│  └──────────────────────────────────────────┘   │
└──────────────────────────────────────────────────┘
            ↓
┌──────────────────────────────────────────────────┐
│  External Systems & Tools                        │
│  - Docker daemon (REST API)                     │
│  - Grype CLI tool                               │
│  - Syft CLI tool                                │
│  - OpenAI API / Anthropic API / Ollama          │
│  - GitHub API                                   │
└──────────────────────────────────────────────────┘
```

### 2.2 Module Responsibilities

#### threat_radar/cli/

**Files:** app.py, cve.py, sbom.py, ai.py, report.py, docker.py, config.py, hash.py, enrich.py

**Responsibilities:**
- CLI command definitions using Typer framework
- Argument parsing and validation
- User I/O (console output, Rich formatting)
- Command orchestration
- Error handling and user-friendly messages

**Key Pattern:** Typer decorators for command registration

#### threat_radar/core/

**Files:**
- docker_integration.py - Docker SDK wrapper
- container_analyzer.py - Container analysis orchestration
- package_extractors.py - Per-distro package parsing
- grype_integration.py - Vulnerability scanning wrapper
- syft_integration.py - SBOM generation wrapper
- github_integration.py - GitHub API wrapper
- cve_storage_manager.py - CVE result persistence

**Responsibilities:**
- Wrapping external tools/SDKs
- Domain model definitions
- Business logic orchestration
- External integration

**Key Pattern:** Adapter/Wrapper pattern for external tools

#### threat_radar/ai/

**Files:**
- llm_client.py - LLM abstraction and implementations
- vulnerability_analyzer.py - AI analysis engine
- prioritization.py - Prioritization logic
- remediation_generator.py - Fix recommendation generation
- prompt_templates.py - LLM prompt engineering

**Responsibilities:**
- LLM provider abstraction
- Prompt engineering
- AI-powered analysis

**Key Pattern:** Abstract factory and strategy patterns

#### threat_radar/utils/

**Files:**
- cli_context.py - Global CLI state
- config_manager.py - Configuration management
- comprehensive_report.py - Report generation (builder pattern)
- report_formatters.py - Output format strategies
- report_templates.py - Data models for reports
- cve_storage.py - Storage management
- sbom_storage.py - SBOM storage

**Responsibilities:**
- Cross-cutting concerns (logging, configuration)
- Utilities and helpers
- Storage/persistence

**Key Pattern:** Singleton for global state

---

## 3. KEY INTEGRATION PATTERNS

### 3.1 Docker Analysis Workflow

```python
# Workflow orchestration showing integration
class ContainerAnalyzer:
    def __init__(self, syft_client=None):
        self.docker_client = DockerClient()  # Docker wrapper
        self._syft_client = syft_client
    
    def analyze_container_with_sbom(self, image_name: str) -> ContainerAnalysis:
        # Step 1: Get image metadata using Docker wrapper
        image_info = self.docker_client.inspect_image(image_name)
        
        # Step 2: Detect distro to extract metadata
        distro, version = self._detect_distro(image_name)
        
        # Step 3: Generate SBOM using Syft wrapper
        sbom_data = self._syft_client.scan_docker_image(
            image_name,
            output_format=SBOMFormat.SYFT_JSON,
            scope="squashed"
        )
        
        # Step 4: Convert SBOM packages to Package objects
        packages = convert_sbom_to_packages(
            sbom_data,
            format="syft",
            include_types=None
        )
        
        # Step 5: Return structured ContainerAnalysis
        analysis = ContainerAnalysis(
            image_name=image_name,
            image_id=image_info['Id'],
            distro=distro,
            packages=packages
        )
        
        return analysis
```

**Demonstrates:**
- Composition of adapters/wrappers
- Data transformation through layers
- Separation of concerns

### 3.2 Vulnerability Scanning Workflow

```python
# CLI command showing end-to-end workflow
@app.command("scan-image")
def scan_docker_image(image: str, severity: Optional[str] = None):
    # 1. Initialize Grype wrapper
    grype = GrypeClient()
    
    # 2. Scan using Grype
    result: GrypeScanResult = grype.scan_docker_image(
        image,
        output_format=GrypeOutputFormat.JSON
    )
    
    # 3. Filter by severity
    if severity:
        min_severity = GrypeSeverity(severity.lower())
        result = result.filter_by_severity(min_severity)
    
    # 4. Save to storage if requested
    if auto_save:
        save_to_cve_storage(result)
    
    # 5. Format and display output
    console.print_result(result)
```

### 3.3 AI Analysis Workflow

```python
# Workflow showing AI provider abstraction
def analyze_scan(scan_result: GrypeScanResult):
    # 1. Get LLM client using factory
    llm_client = get_llm_client(
        provider="openai",  # or "anthropic" or "ollama"
        model="gpt-4o"
    )
    
    # 2. Create analyzer with abstracted client
    analyzer = VulnerabilityAnalyzer(llm_client=llm_client)
    
    # 3. Analyze scan
    analysis: VulnerabilityAnalysis = analyzer.analyze_scan_result(
        scan_result,
        batch_mode="auto"
    )
    
    # 4. Save analysis
    save_to_ai_storage(analysis)
    
    # 5. Return results
    return analysis
```

**Demonstrates:**
- Factory pattern for LLM selection
- Bridge pattern for abstraction
- Workflow orchestration

### 3.4 Report Generation Workflow

```python
# Workflow showing builder pattern and strategies
def generate_report_command(scan_file: str, format: str = "html"):
    # 1. Load scan results
    scan_result = load_json_file(scan_file)
    
    # 2. Create report generator (builder)
    generator = ComprehensiveReportGenerator(
        ai_provider="openai",
        ai_model="gpt-4o"
    )
    
    # 3. Build comprehensive report
    report: ComprehensiveReport = generator.generate_report(
        scan_result,
        report_level=ReportLevel.DETAILED,
        include_executive_summary=True,
        include_dashboard_data=True
    )
    
    # 4. Select formatter strategy
    formatters = {
        'json': JSONFormatter(),
        'markdown': MarkdownFormatter(),
        'html': HTMLFormatter(),
    }
    formatter = formatters[format]
    
    # 5. Format and save
    output = formatter.format(report)
    save_file(output, f"report.{format}")
```

---

## 4. CONFIGURATION MANAGEMENT APPROACH

### 4.1 Hierarchical Configuration

```python
# Configuration loaded in order of precedence:
# 1. Default values (in dataclasses)
# 2. Configuration files (if found)
# 3. Environment variables
# 4. Command-line arguments (highest priority)

@dataclass
class ThreatRadarConfig:
    scan: ScanDefaults = field(default_factory=ScanDefaults)
    ai: AIDefaults = field(default_factory=AIDefaults)
    report: ReportDefaults = field(default_factory=ReportDefaults)
    output: OutputDefaults = field(default_factory=OutputDefaults)
    paths: PathDefaults = field(default_factory=PathDefaults)

class ConfigManager:
    DEFAULT_CONFIG_LOCATIONS = [
        Path.cwd() / ".threat-radar.json",
        Path.cwd() / "threat-radar.json",
        Path.home() / ".threat-radar" / "config.json",
        Path.home() / ".config" / "threat-radar" / "config.json",
    ]
    
    def _load_config(self):
        """Load from first found location"""
        config_file = self._find_config_file()
        if config_file:
            with open(config_file) as f:
                data = json.load(f)
            self.config = ThreatRadarConfig.from_dict(data)
    
    def _apply_env_overrides(self):
        """Environment variables override file config"""
        if os.getenv('THREAT_RADAR_SEVERITY'):
            self.config.scan.severity = os.getenv('THREAT_RADAR_SEVERITY')
        if os.getenv('AI_PROVIDER'):
            self.config.ai.provider = os.getenv('AI_PROVIDER')
    
    def get(self, key: str, default: Any = None) -> Any:
        """Dot-notation access: 'scan.severity'"""
        parts = key.split('.')
        value = self.config
        for part in parts:
            if hasattr(value, part):
                value = getattr(value, part)
            else:
                return default
        return value
```

### 4.2 CLI Global Options Callback

```python
# Main app callback sets up global context
@app.callback()
def main_callback(
    config_file: Optional[Path] = typer.Option(None, "--config", "-c"),
    verbosity: int = typer.Option(1, "--verbose", "-v", count=True),
    quiet: bool = typer.Option(False, "--quiet", "-q"),
    output_format: str = typer.Option("table", "--output-format", "-f"),
    no_color: bool = typer.Option(False, "--no-color"),
    no_progress: bool = typer.Option(False, "--no-progress"),
):
    # Create global context with merged configuration
    context = CLIContext.create(
        config_file=config_file,
        verbosity=verbosity,
        output_format=output_format,
        no_color=no_color,
        no_progress=no_progress,
    )
    set_cli_context(context)
```

---

## 5. ERROR HANDLING PATTERNS

### 5.1 Custom Exception Hierarchy

```python
# Wrapping SDK exceptions
class DockerClient:
    def _connect(self) -> None:
        try:
            self._client = docker.from_env()
        except DockerException as e:
            # Transform Docker SDK exception to meaningful error
            raise ConnectionError(
                "Could not connect to Docker daemon. "
                "Ensure Docker is running and accessible."
            ) from e

# Tool availability checking
class GrypeClient:
    def _check_installation(self) -> None:
        try:
            subprocess.run([self.grype_path, "version"], timeout=5)
        except FileNotFoundError:
            raise RuntimeError(
                f"Grype not found at {self.grype_path}. "
                "Install it from: https://github.com/anchore/grype#installation"
            )
```

### 5.2 Retry Logic with Exponential Backoff

```python
from tenacity import retry, stop_after_attempt, wait_exponential

class OpenAIClient(LLMClient):
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def generate_json(self, prompt: str, temperature: float = 0.7) -> Dict:
        """Automatically retry up to 3 times with exponential backoff"""
        response = self.client.chat.completions.create(...)
        return self._parse_response(response)
```

### 5.3 Context Manager for Error Handling

```python
@contextmanager
def handle_cli_error(operation: str, console: Console):
    """Context manager for CLI error handling"""
    try:
        yield
    except KeyboardInterrupt:
        console.print("[red]Operation cancelled by user[/red]")
        raise SystemExit(1)
    except Exception as e:
        console.print(f"[red]Error during {operation}: {str(e)}[/red]")
        raise SystemExit(1)

# Usage
@app.command()
def scan_image(image: str):
    with handle_cli_error("scanning image", console):
        result = grype.scan_docker_image(image)
```

---

## 6. DEPENDENCY INJECTION PATTERNS

### 6.1 Constructor Injection

```python
class VulnerabilityAnalyzer:
    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,  # Injected dependency
        provider: Optional[str] = None,
        model: Optional[str] = None,
    ):
        # Use provided client or create one
        self.llm_client = llm_client or get_llm_client(provider, model)

class ContainerAnalyzer:
    def __init__(self, syft_client=None):  # Optional injection
        self.docker_client = DockerClient()  # Create own dependency
        self._syft_client = syft_client or self._create_syft_client()
```

### 6.2 Factory Function Injection

```python
# Functions receive factory function that creates dependencies
def analyze_vulnerabilities(
    scan_result: GrypeScanResult,
    get_llm_client: Callable = get_llm_client,  # Injectable factory
):
    client = get_llm_client(provider="openai")
    analyzer = VulnerabilityAnalyzer(llm_client=client)
    return analyzer.analyze_scan_result(scan_result)
```

---

## 7. TESTING APPROACH

### 7.1 Design for Testability

```python
# Interfaces allow mocking
class LLMClient(ABC):
    @abstractmethod
    def generate(self, prompt: str) -> str:
        pass

# Test can inject mock
class MockLLMClient(LLMClient):
    def generate(self, prompt: str) -> str:
        return '{"analysis": "mock"}'

def test_analyzer():
    mock_client = MockLLMClient()
    analyzer = VulnerabilityAnalyzer(llm_client=mock_client)
    result = analyzer.analyze_scan_result(scan_data)
    assert result is not None

# Context managers have reset methods for test isolation
def test_config():
    config1 = get_config_manager(Path("config1.json"))
    reset_config_manager()  # Clear singleton
    config2 = get_config_manager(Path("config2.json"))
    assert config1 is not config2
```

### 7.2 Fixture Organization

```python
# Tests use fixtures directory for test data
tests/
├── fixtures/
│   ├── grype_output.json
│   ├── sbom.json
│   └── config.json
├── test_docker_integration.py
├── test_ai_integration.py
├── test_comprehensive_report.py
└── test_batch_processing.py
```

---

## 8. CODE ORGANIZATION PRINCIPLES

### 8.1 Separation of Concerns

| Module | Responsibility |
|--------|-----------------|
| CLI (cli/) | Command handling, user I/O, argument parsing |
| Core (core/) | Business logic, external integrations, domain models |
| AI (ai/) | LLM abstraction, AI analysis, prompt engineering |
| Utils (utils/) | Cross-cutting concerns, storage, formatting |

### 8.2 Dependency Direction

```
CLI Commands
    ↓
CLI Context & Config
    ↓
Business Logic (core/, ai/)
    ↓
External Systems (Docker, Grype, LLMs, GitHub)
```

Dependency flows inward - external systems don't depend on business logic.

### 8.3 Immutability and Data Flow

```python
# Data flows through immutable domain objects
scan_result: GrypeScanResult  # Immutable container

# Filtering returns new instance
filtered_result = scan_result.filter_by_severity(HIGH)

# Building reports creates new objects
report = generator.generate_report(scan_result)

# Formatters consume reports without modifying
json_output = JSONFormatter().format(report)
```

---

## CONCLUSION

The Threat Radar codebase demonstrates professional software architecture through:

1. **Design Pattern Application**: Factory, Strategy, Adapter, Singleton, Builder, Bridge patterns used appropriately
2. **Layered Architecture**: Clear separation between CLI, business logic, integrations, and external systems
3. **Abstraction**: LLM providers abstracted behind common interface; external tools wrapped consistently
4. **Configuration Management**: Hierarchical configuration with precedence rules
5. **Error Handling**: Meaningful exception translation, retry logic, context managers
6. **Testability**: Dependency injection, interfaces, fixture organization
7. **Domain-Driven Design**: Rich domain models with behavior (GrypeScanResult.filter_by_severity)
8. **Composability**: Small, focused modules that compose into larger workflows

This architecture enables:
- Easy addition of new AI providers (just add new LLMClient)
- Easy addition of new package managers (just add new Extractor)
- Easy addition of new output formats (just add new Formatter)
- Easy testing through dependency injection and mocking
- Clear data flow from CLI through business logic to external systems

